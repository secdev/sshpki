#! /usr/bin/env python


import os
import sys
import re
import shutil
import atexit
import traceback
import base64
import tarfile
from subprocess import check_call, check_output, CalledProcessError, STDOUT
import datetime
import readline
import functools
from StringIO import StringIO
import cmd
import tempfile
from sqlobject import SQLObject,BLOBCol,UnicodeCol,IntCol,StringCol,BoolCol,DateTimeCol,ForeignKey,MultipleJoin,connectionForURI,sqlhub


DBVERSION = 1
DEFAULTDB = "~/.reblaze/sshpki.db"
TMPPATH   = "/dev/shm" # use memory only




##  _____     _    _
## |_   _|_ _| |__| |___ ___
##   | |/ _` | '_ \ / -_|_-<
##   |_|\__,_|_.__/_\___/__/
##

class Meta(SQLObject):
    version = IntCol()
    pkiname = UnicodeCol()

class CA(SQLObject):
    name = UnicodeCol(unique=True)
    key = ForeignKey("Key")
    serial = IntCol(default=0)
    hostca = BoolCol(default=False)
    signed = MultipleJoin("Key", joinColumn="ca_id")
    krl = BLOBCol()

class Key(SQLObject):
    name = UnicodeCol(unique=True)
    bits = IntCol()
    pubkey = StringCol(unique=True)
    revoked = BoolCol(default=False)
    exported = BoolCol(default=False)
    certs = MultipleJoin("Cert", joinColumn="key_id")
    ca = ForeignKey("CA", default=None)
    is_ca = BoolCol(default=False)
    def delete_key(self):
        for cert in self.certs:
            cert.delete_cert()
        self.delete(self.id)

class Cert(SQLObject):
    ca = ForeignKey("CA")
    name = StringCol()
    key = ForeignKey("Key", cascade=False)
    serial = IntCol(default=-1)
    profile = ForeignKey("Profile")
    cert = StringCol(unique=True)
    start_time = DateTimeCol(default=None)
    end_time = DateTimeCol(default=None)
    def delete_cert(self):
        self.profile.delete_profile()
        self.delete(self.id)

class Profile(SQLObject):
    principals = StringCol(default=None)
    force_command = StringCol(default=None)
    source_address = StringCol(default=None)
    agent_forwarding = BoolCol(default=None)
    x11_forwarding = BoolCol(default=None)
    port_forwarding = BoolCol(default=None)
    pty = BoolCol(default=None)
    user_rc = BoolCol(default=None)
    validity = StringCol(default=None)
    def delete_profile(self):
        self.delete(self.id)

class ProfileTemplate(SQLObject):
    name = UnicodeCol(unique=True)
    profile = ForeignKey("Profile")

class FileExport(SQLObject):
    key = ForeignKey("Key", cascade=True)
    filename = StringCol()

class YubikeyExport(SQLObject):
    key = ForeignKey("Key", cascade=True)
    yubikey = ForeignKey("Yubikey", cascade=False)
    serial = IntCol()

class Yubikey(SQLObject):
    export = ForeignKey("YubikeyExport", cascade=None, default=None)
    owner = StringCol(default=None)
    serial = StringCol(default=None, unique=True)
    mgmkey = StringCol(default=None)



##  _   _ _   _ _
## | | | | |_(_) |
## | |_| |  _| | |
##  \___/ \__|_|_|
##

def get_random(nb):
    return open("/dev/random").read(nb)

def rl_input(prompt, prefill=''):
   readline.set_startup_hook(lambda: readline.insert_text(prefill))
   try:
      return raw_input(prompt)
   finally:
      readline.set_startup_hook()

def ask(q, r, default=""):
    r = [x.lower() for x in r]
    q2 = "%s ? (%s) " % (q, "/".join(r))
    if default:
        q2 += "[%s] " % default

    while True:
        ans = raw_input(q2).lower()
        if not ans:
            ans = default
        if ans and ans in r:
            break
    return ans

def passwdgen():
    return get_random(16).encode("hex")

def get_tmpfile(options):
    return tempfile.NamedTemporaryFile(dir=options.tmp)

def ensure_arg(name):
    def deco(f):
        @functools.wraps(f)
        def wrapper(self, arg):
            if not arg:
                arg = rl_input("Enter %s: " % name)
            return f(self, arg)
        return wrapper
    return deco

##  ___ _  _____
## | _ \ |/ /_ _|  ___ _ __ ___
## |  _/ ' < | |  / _ \ '_ (_-<
## |_| |_|\_\___| \___/ .__/__/
##                    |_|

def export_key(options, key, privfname, pwd):
        print "Please export secret key to yubikey/file/paper backup. It will then be deleted"
        kecli = KeyExportCLI(options, key, privfname, pwd)
        while True:
            kecli.cmdloop_catcherrors()
            if key.exported:
                msg = "Secret key has been exported. It is going to be deleted. Last chance to do another export. Delete?"
            else:
                msg = "Secret key has not been exported. Are you sure you want to delete it?"
            a = ask(msg, "yn")
            if a == "y":
                break
        os.unlink(privfname)

def create_key(options, name, bits):
    tmpkey = os.path.join(options.tmp, name)
    try:
        pwd = passwdgen()
        check_call([
            "ssh-keygen", "-f", tmpkey,
            "-P", pwd,
            "-b", str(bits),
            "-C", name
        ], stderr=STDOUT)
    except CalledProcessError,e:
        print "ERROR: %s" % e.output
        raise
    else:
        k = Key(name=name, bits=bits, pubkey=open(tmpkey+".pub").read())
        export_key(options, k, tmpkey, pwd)
        return k

def get_profile_template(options):
    while True:
        print "Choose profile:"
        print " 0. Create a new profile"
        lst = []
        for tmpl in ProfileTemplate.select():
            lst.append(tmpl)
            print "%2i. %-20s %s" % (
                len(lst),
                tmpl.name,
                profile_summary(tmpl.profile)
            )
        ans = int(ask("profile: ", map(str,range(len(lst)+1))))
        if ans == 0:
            cli = ProfileTemplateCLI(options)
            cli.cmdloop_catcherrors()
        else:
            tmpl = lst[ans-1]
            break
    return tmpl

def get_cert_validity(cert_file):
    cmd = ["ssh-keygen", "-L", "-f", cert_file]
    o = check_output(cmd)
    valid = re.search(".*Valid: (.*)$", o, re.MULTILINE).groups()
    if not valid or valid and "forever" in valid[0]:
        return None, None
    else:
        start_s,end_s = re.search("^from (.*) to (.*)$", valid[0]).groups()
        start = datetime.datetime.strptime(start_s, "%Y-%m-%dT%H:%M:%S")
        end = datetime.datetime.strptime(end_s, "%Y-%m-%dT%H:%M:%S")
        return start, end

def sign_key(options, cert_name, ca, key, profile):
    opts = []
    if ca.hostca:
        opts += ["-h"]
    profile = profile
    if profile.validity:
        opts += ["-V", profile.validity]
    if profile.principals:
        opts += ["-n", profile.principals]
    for k in ["force_command", "source_address",
              "agent_forwarding", "x11_forwarding",
              "port_forwarding", "pty", "user_rc" ]:
        v = getattr(profile, k)
        k = k.replace("_", "-")
        if v is False:
            opts += ["-O", "no-%s" % k]
        elif v and v is not True:
            opts += ["-O", "%s=%s" % (k,v)]
    print "Where is the private CA key ?"
    print " 0. Enter a file path"
    choice = [None]
    for k in FileExport.selectBy(key=ca.key):
        print "%2i. file %s" % (len(choice), k.filename)
        choice.append(k)
    for k in YubikeyExport.selectBy(key=ca.key):
        print "%2i. yubikey with serial #%i" % (len(choice), k.serial)
        choice.append(k)
    ans = int(ask("private key source: ", map(str,range(len(choice)))))
    k = choice[ans]
    if k is None:
        ans = rl_input("Private key filename: ")
        cmd = [ "ssh-keygen", "-s", ans ]
    elif type(k) is FileExport:
        cmd = [ "ssh-keygen", "-s", k.filename ]
    elif type(k) is YubikeyExport:
        print "Not implemented"
        return
    with get_tmpfile(options) as tmppub:
        tmppub.write(key.pubkey)
        tmppub.flush()
        cmd += [
            "-C", cert_name,
            "-I", cert_name,
            "-b", str(options.cert_bits),
            "-z", str(ca.serial),
        ] + opts + [ tmppub.name ]
        try:
            check_call(cmd)
        except CalledProcessError,e:
            print "ERROR: %s" % e.output
            return
        certfile = "%s-cert.pub" % tmppub.name

    start_time,end_time = get_cert_validity(certfile)
    profvalues = {k:getattr(profile, k) for k in profile.sqlmeta.columns}
    prof2 = Profile(**profvalues)
    key.ca = ca
    certcontent = open(certfile).read()
    cert = Cert(ca=ca, key=key, name=cert_name, profile=prof2, 
                serial=ca.serial, cert=certcontent)
    ca.serial += 1
    if start_time:
        cert.start_time = start_time
    if end_time:
        cert.end_time = end_time
    return cert


def create_CA(options, ca_name, key, hostca=False):
    key.is_ca = True
    # create empty KRL
    with get_tmpfile(options) as krl_file:
        check_call([ "ssh-keygen", "-kf", krl_file.name ])
        krl = krl_file.read()
    ca = CA(name=ca_name, key=key, krl=krl, hostca=hostca)

def update_krl(options, ca):
    rev = []
    for k in ca.signed:
        if k.revoked:
            kfile = get_tmpfile(options)
            kfile.write(k.pubkey)
            kfile.flush()
            rev.append(kfile)
    with get_tmpfile(options) as krl:
        with get_tmpfile(options) as ca_pub:
            ca_pub.write(ca.key.pubkey)
            ca_pub.flush()
            cmd = [ "ssh-keygen", "-kf", krl.name,
                    "-s", ca_pub.name ] + [f.name for f in rev]
            check_call(cmd)
        ca.krl = krl.read()


def revoke_key(options, key_name):
    keys = list(Key.selectBy(name=key_name))
    if len(keys) == 0:
        print "Key [%s] not found" % key_name
        return
    key = keys[0]
    if ask("Are you sure you want to revoke key [%s]" % key.name, "yn") == "n":
            print "Revocation aborted."
            return
    if key.is_ca:
        if ask("Key [%s] is a CA. Are you sure you want to revoke it" % key.name, "yn") == "n":
            print "Revocation aborted."
            return
    key.revoked = True
    for cert in key.certs:
        update_krl(options, cert.ca)


def profile_summary(prof):
    s = []
    for k in [ "principals", "force_command", "source_address", "agent_forwarding",
               "x11_forwarding", "port_forwarding", "pty", "user_rc", "validity" ]:
        v = getattr(prof, k)
        if v is False or v is not True and v:
            s.append("%s=%s" % (k, v))
    if not s:
        s = ["no limits"]
    return ", ".join(s)

## __   __    _    _ _                                              _
## \ \ / /  _| |__(_) |_____ _  _   __ ___ _ __  _ __  __ _ _ _  __| |___
##  \ V / || | '_ \ | / / -_) || | / _/ _ \ '  \| '  \/ _` | ' \/ _` (_-<
##   |_| \_,_|_.__/_|_\_\___|\_, | \__\___/_|_|_|_|_|_\__,_|_||_\__,_/__/
##                           |__/

def yubikey_get_serial_and_mode():
    try:
        o = check_output(["ykneomgr", "--get-serialno"])
        serial = o.strip()
        return serial, True
    except CalledProcessError:
        try:
            o = check_output(["ykinfo", "-s"])
            serial = o.split(" ",2)[1].strip()
            return serial, False
        except CalledProcessError:
            print "No yubikey found."
            return None,None


def yubikey_enroll(owner):
    serial, ccid = yubikey_get_serial_and_mode()
    if serial is None:
        print "No yubikey found."
        return
    ans = ask("This operation will erase all material on yubikey [%s]. Continue" % serial, "yn")
    if ans == "n":
        print "aborted."
        return
    if ccid:
        check_call(["ykneomgr", "--set-mode", "1"])
    else:
        check_output("ykpersonalize -y -m 1 2>&1", shell=True)
    raw_input("Set mode to CCID. Please unplug and replug the yubikey and press enter.")

    # Now we block PIN and PUK to unlock the reset function
    while True:
        o = check_output("yubico-piv-tool -P00000000 -N00000000 -a change-pin 2>&1 || true", shell=True)
        if o.startswith("Failed"):
            continue
        break
    while True:
        o = check_output("yubico-piv-tool -P00000000 -N00000000 -a unblock-pin 2>&1 || true", shell=True)
        if o.startswith("Failed"):
            continue
        break
    # PIN and PUK are blocked. We can erase all material
    print "Resetting material"
    check_call(["yubico-piv-tool", "-a", "reset"])
    mgmkey = get_random(24).encode("hex")
    Yubikey(serial=serial, mgmkey=mgmkey, owner=owner)
    check_call(["yubico-piv-tool", "-a", "set-mgm-key", "-n", mgmkey])
    print "A new management key has been set"
    print "PUK and PIN must be between 6 and 8 digits"
    check_call(["yubico-piv-tool", "-k", mgmkey, "-a", "change-puk", "-P12345678"])
    check_call(["yubico-piv-tool", "-k", mgmkey, "-a", "change-pin", "-P123456"])

##   ___ _    ___
##  / __| |  |_ _|
## | (__| |__ | |
##  \___|____|___|
##

class CLI(cmd.Cmd):
    def cmdloop_catcherrors(self):
        while True:
            try:
                self.cmdloop()
            except Exception,e:
                traceback.print_exc()
                continue
            break
    def do_EOF(self, line):
        print
        return True
    def emptyline(self):
        pass
    def do_shell(self, arg):
        """shell
        pass arg to system shell"""
        os.system(arg)
    def do_python(self, arg):
        import code
        code.interact(local=globals())
    def prompt_push(self, *args):
        self.oldlevels = self.options.levels[:]
        self.options.levels += args
        self.prompt = "/".join(self.options.levels)+"> "

    def __del__(self):
        self.options.levels = self.oldlevels

    def _complete(self, obj, val, field="name"):
        matches = obj.select("%s like '%s%%'" % (field,val))
        return [getattr(o, field) for o in matches]

    def _complete_ca(self, text, line, begidx, endidx):
        return self._complete(CA, text)
    def _complete_key(self, text, line, begidx, endidx):
        return self._complete(Key, text)
    def _complete_profiletemplate(self, text, line, begidx, endidx):
        return self._complete(ProfileTemplate, text)
    def _complete_yubikey(self, text, line, begidx, endidx):
        return self._complete(Yubikey, text, "serial")



class MainCLI(CLI):
    def __init__(self, options):
        CLI.__init__(self)
        self.options = options
        m = Meta.select()[0]
        self.pkiname = m.pkiname
        self.prompt_push(self.pkiname)

    ### commands

    def do_ca(self, arg):
        cli = CACLI(self.options)
        cli.cmdloop_catcherrors()

    def do_keys(self, arg):
        cli = KeyCLI(self.options)
        cli.cmdloop_catcherrors()

    def do_certs(self, arg):
        cli = CertCLI(self.options)
        cli.cmdloop_catcherrors()

    def do_profiles(self, arg):
        cli = ProfileTemplateCLI(self.options)
        cli.cmdloop_catcherrors()

    def do_yubikey(self, arg):
        cli = YubikeyCLI(self.options)
        cli.cmdloop_catcherrors()

class CACLI(CLI):
    def __init__(self, options):
        CLI.__init__(self)
        self.options = options
        self.prompt_push("CA")

    complete_use = CLI._complete_ca
    complete_show = CLI._complete_ca

    def do_ls(self, arg):
        for ca in CA.select():
            print "%-30s %8s %s signed %2i keys" % (ca.name,
                                                    "REVOKED" if ca.key.revoked else "active",
                                                    "HOST" if ca.hostca else "USER",
                                                    len(ca.signed))

    @ensure_arg("CA")
    def do_add(self, ca_name):
        ans = ask("Is this a [H]ost CA or a [U]ser CA", "hu")
        k = create_key(self.options, ca_name, self.options.ca_bits)
        create_CA(self.options, ca_name, k, hostca=(ans == "h"))

    @ensure_arg("CA")
    def do_use(self, ca_name):
        ca = CA.selectBy(name=ca_name)[0]
        cli = UseCLI(self.options, ca)
        cli.cmdloop_catcherrors()

    @ensure_arg("CA")
    def do_show(self, ca):
        cas = list(CA.selectBy(name=ca))
        if len(cas) == 0:
            print "CA [%s] not found" % ca
        else:
            print "cert-authority %s" % cas[0].key.pubkey

class CertCLI(CLI):
    def __init__(self, options):
        CLI.__init__(self)
        self.options = options
        self.prompt_push("certs")

    complete_show = CLI._complete_key

    @ensure_arg("cert")
    def do_show(self, cert):
        keys = list(Key.selectBy(name=cert))
        if len(keys) == 0:
            print "key for cert [%s] not found" % cert
        else:
            for c in keys[0].certs:
                print c.cert

    def do_ls(self, arg):
        for cert in Cert.select():
            if cert.start_time and cert.end_time:
                validity = "from %s to %s" % (
                    cert.start_time.strftime("%c"),
                    cert.end_time.strftime("%c")
                )
            elif cert.end_time:
                validity = "until %s" % cert.end_time.strftime("%c")
            else:
                validity=""
            print "{k.name:<20} {ca.name:<15} {cert.serial} {profile} {validity}".format(
                k=cert.key, ca=cert.ca, cert=cert, validity=validity, profile=profile_summary(cert.profile))



class KeyCLI(CLI):
    def __init__(self, options):
        CLI.__init__(self)
        self.options = options
        self.prompt_push("keys")

    complete_revoke = CLI._complete_key
    complete_del = CLI._complete_key
    complete_show = CLI._complete_key

    def do_ls(self, arg):
        for k in Key.select():
            ca = "CA" if k.is_ca else "user"
            signed = "" if k.is_ca else (("signed by [%s]" % k.ca.name) if k.ca else "never signed")
            status = "REVOKED" if k.revoked else "ACTIVE" 
            print "%-30s %-4s %-7s  %4i bits  %s" % (k.name, ca, status, k.bits, signed)

    @ensure_arg("key")
    def do_show(self, key):
        keys = list(Key.selectBy(name=key))
        if len(keys) == 0:
            print "key [%s] not found" % cert
        else:
            print keys[0].pubkey

    @ensure_arg("key")
    def do_del(self, key_name):
        keys = list(Key.selectBy(name=key_name))
        if len(keys) == 0:
            print "Key [%s] not found" % key_name
            return
        key = keys[0]
        key.delete_key()

    @ensure_arg("key")
    def do_revoke(self, key_name):
        revoke_key(self.options, key_name)

    @ensure_arg("key file")
    def do_import(self, key_file):
        pubkey = open(key_file).read()
        o = check_output(["ssh-keygen", "-lf", key_file])
        bits = int(o.split(" ",1)[0])
        priv = False
        if not pubkey.startswith("ssh-rsa"):
            pubkey = check_output(["ssh-keygen", "-yf", key_file])
            priv = True
        name = rl_input("name: ")
        k = Key(name=name, bits=bits, pubkey=pubkey)
        if priv:
            FileExport(key=k, filename=key_file)


class UseCLI(CLI):
    def __init__(self, options, ca):
        CLI.__init__(self)
        self.ca = ca
        self.options = options
        self.prompt_push(ca.name)

    complete_sign = CLI._complete_key
    complete_resign = CLI._complete_key
    complete_revoke = CLI._complete_key
    complete_show_key = CLI._complete_key
    complete_show_cert = CLI._complete_key
    complete_export = CLI._complete_key

    def do_show(self, arg):
        print "cert-authority %s" % self.ca.key.pubkey

    @ensure_arg("key")
    def do_show_key(self, name):
        keys = list(Key.selectBy(name=name))
        if not keys:
            print "key [%s] not found" % name
            return
        key = keys[0]
        if key.ca != self.ca:
            if key.ca:
                print "Warning: this key is not signed by the current CA [%s] but by CA [%s]" % (self.ca.name, key.ca.name)
            else:
                print "Warning; this key is not signed by any CA yet."
        print key.pubkey

    @ensure_arg("key")
    def do_show_cert(self, name):
        keys = list(Key.selectBy(name=name))
        if not keys:
            print "key [%s] not found" % name
            return
        key = keys[0]
        if not key.certs:
            print "No certs found for key [%s]" % name
        else:
            for cert in key.certs:
                if cert.ca != self.ca:
                    print "Warning: this cert is not signed by the current CA [%s] but by CA [%s]" % (self.ca.name, cert.ca.name)
                print cert.cert

    @ensure_arg("key")
    def do_add(self, key_name):
        cert_name = rl_input("Enter cert name: ", "%s_%i" % (key_name, self.ca.serial))
        key = create_key(self.options, key_name, self.options.cert_bits)
        proftmpl = get_profile_template(self.options)
        sign_key(self.options, cert_name, self.ca, key, proftmpl.profile)

    @ensure_arg("key")
    def do_sign(self, key_name):
        cert_name = rl_input("Enter cert name: ", "%s_%i" % (key_name, self.ca.serial))
        keys = list(Key.selectBy(name=key_name))
        if len(keys) == 0:
            print "key [%s] not found" % key_name
        else:
            key = keys[0]
            proftmpl = get_profile_template(self.options)
            sign_key(self.options, cert_name, self.ca, key, proftmpl.profile)

    @ensure_arg("key")
    def do_resign(self, key_name):
        keys = list(Key.selectBy(name=key_name))
        if len(keys) == 0:
            print "key [%s] not found" % key_name
        else:
            key = keys[0]
            if not key.certs:
                print "Error: Key [%s] has never been signed yet" % key_name
                return
            cert = max(key.certs, key=lambda x:x.serial)
            cert_name = cert.name
            num = "_%i" % cert.serial
            if cert_name.endswith(num):
                cert_name = cert_name[:-len(num)]
            cert_name += "_%i" % self.ca.serial
            sign_key(self.options, cert_name, self.ca, key, cert.profile)

    @ensure_arg("KRL file")
    def do_export_krl(self, file_name):
        open(file_name, "w").write(self.ca.krl)

    def do_ls(self, arg):
        for k in self.ca.signed:
            status = "REVOKED" if k.revoked else "ACTIVE" 
            print "%-30s %-7s %4i bits:" % (k.name, status, k.bits)
            for cert in k.certs:
                if cert.start_time and cert.end_time:
                    validity = "from %s to %s" % (
                        cert.start_time.strftime("%c"),
                        cert.end_time.strftime("%c")
                    )
                elif cert.end_time:
                    validity = "until %s" % cert.end_time.strftime("%c")
                else:
                    validity=""
                print "  -> certificate {cert.name:<10} {cert.serial:>3} {profile} {validity}".format(
                    cert=cert, validity=validity, profile=profile_summary(cert.profile))

    @ensure_arg("key")
    def do_revoke(self, key_name):
        revoke_key(self.options, key_name)

    @ensure_arg("key")
    def do_export(self, name):
        keys = list(Key.selectBy(name=name))
        if not keys:
            print "key [%s] not found" % name
            return
        key = keys[0]
        cert = None
        t = datetime.datetime.now()
        for c in key.certs:
            if c.start_time and c.start_time > t:
                continue
            if c.end_time and c.end_time < t:
                continue
            if not cert:
                cert = c
            elif not c.end_time or c.end_time > cert.end_time:
                cert = c
            if not cert.end_time:
                break
        if not cert:
            print "No valid cert found for key [%s]" % name
            return


        tarstr=StringIO()
        t=tarfile.open(fileobj=tarstr, mode="w:gz")

        ti = tarfile.TarInfo("id_%s.pub" % key.name)
        ti.size = len(key.pubkey)
        ti.type=tarfile.REGTYPE
        t.addfile(ti, StringIO(key.pubkey))

        ti = tarfile.TarInfo("id_%s-cert.pub" % key.name)
        ti.size = len(cert.cert)
        ti.type=tarfile.REGTYPE
        t.addfile(ti, StringIO(cert.cert))

        t.close()

        tarstr.getvalue()
        cmd = "echo %s|base64 -d|tar zx" % (base64.b64encode(tarstr.getvalue())).decode()
        print(cmd)


class KeyExportCLI(CLI):
    def __init__(self, options, key, privfname, pwd):
        CLI.__init__(self)
        self.options = options
        self.privfname = privfname
        self.key = key
        self.pwd = pwd
        self.exported = False
        self.prompt_push(key.name, "export")

    def mark_as_exported(self):
        if not self.exported:
            self.key.exported = True
            self.exported = True

    @ensure_arg("file")
    def do_file(self, dest):
        with get_tmpfile(self.options) as tmp:
            shutil.copy(self.privfname, tmp.name)
            check_call(["ssh-keygen", "-p", "-P", self.pwd, "-f", tmp.name])
            shutil.copy(tmp.name, dest)
        FileExport(key=self.key, filename=dest)
        self.mark_as_exported()

    def do_yubikey(self, arg):
        serial, ccid = yubikey_get_serial_and_mode()
        if not serial:
            print "No yubikey found. Please insert a yubikey and retry."
            return
        while True:
            yks = list(Yubikey.selectBy(serial=serial))
            if yks:
                yk = yks[0]
                break
            ans = ask("This yubikey is not enrolled in the database. Enroll it ?", "yn")
            if ans == "n":
                print "yubikey export aborted."
                return
            yubikey_enroll()
        # 9a is for authentication, 9c is for signature
        slot = "9c" if self.key.is_ca else "9a"
        cmd = [ "yubico-piv-tool", "-k"+yk.mgmkey, "-s", slot, "-averify-pin", "-aset-chuid", "-aimport-key",
                "-i", self.privfname, "-p", self.pwd, ]
#                 "--pin-policy=never", "--touch-policy=always" ]
        print " ".join(cmd)
        check_call(cmd)
        with get_tmpfile(self.options) as pubkey:
            pubkey.write(self.key.pubkey)
            pubkey.flush()
            cmd = [ "ssh-keygen", "-e", "-m", "pkcs8", "-f", pubkey.name ]
            print " ".join(cmd)
            pkcs8 = check_output(cmd)
        with get_tmpfile(self.options) as cert:
            with get_tmpfile(self.options) as pkcs8key:
                pkcs8key.write(pkcs8)
                pkcs8key.flush()
                cmd = [ "yubico-piv-tool", "-s", slot, "-k", yk.mgmkey,
                        "-averify-pin", "-aselfsign-certificate",
                        "-S", "/CN=SSH key [%s]/" % self.key.name,
                        "-i", pkcs8key.name, "-o", cert.name ]
                print " ".join(cmd)
                check_call(cmd)
            cmd = [ "yubico-piv-tool", "-s", slot, "-k"+yk.mgmkey,
                    "-aimport-certificate", "-i", cert.name ]
            print " ".join(cmd)
            check_call(cmd)
        cmd = [ "yubico-piv-tool", "-astatus" ]
        print " ".join(cmd)
        check_call(cmd)
        YubikeyExport(key=self.key, serial=int(serial), yubikey=yk)
        self.mark_as_exported()

class ProfileTemplateCLI(CLI):
    def __init__(self, options):
        CLI.__init__(self)
        self.options = options
        self.prompt_push("profiles")

    complete_delete = CLI._complete_profiletemplate
    complete_edit = CLI._complete_profiletemplate

    def do_ls(self, arg):
        for tmpl in ProfileTemplate.select():
            print "%-30s %s" % (tmpl.name, profile_summary(tmpl.profile))

    def ask_profile(self, **in_prof):
        prof = {}
        for opt,txt in [
                ("name", "Name"),
                ("principals", "Principals"),
                ("force_command", "Force command"),
                ("source_address", "Enforce source addresses"), ]:
            ans = rl_input("%s: " % txt, in_prof.get(opt, ""))
            prof[opt] = ans
        for opt,txt in [("agent_forwarding", "agent forwarding"),
                        ("port_forwarding", "port forwarding"),
                        ("x11_forwarding", "X11 forwarding"),
                        ("pty", "PTY allocation"),
                        ("user_rc", "user ~/.ssh/rc file"), ]:
            ans = ask("Permit %s" % txt, "yn", in_prof.get(opt, ""))
            prof[opt] = ans == "y"
        while True:
            ans = rl_input("""validity interval
    end or start:end, start or end being
    - YYYYMMDD
    - YYYYMMDDHHMMSS
    - [+-]([0-9]+[wdhms]){1,}):
""", in_prof.get("validity", ""))
            if re.match("(|[0-9]{8}|[0-9]{14}|[+-]([0-9]+(|[sSmMhHdDwW])){1,})$", ans):
                break
            print "invalid date expression"
        prof["validity"] = ans
        return prof

    @ensure_arg("profile")
    def do_add(self, name):
        prof = self.ask_profile(name=name, principals="root,ubuntu")
        name = prof.pop("name")
        p = Profile(**prof)
        t = ProfileTemplate(name=name, profile=p)

    @ensure_arg("profile")
    def do_delete(self, name):
        pt = list(ProfileTemplate.selectBy(name=name))
        if pt:
            p = pt[0].profile
            p.delete(p.id)
            pt[0].delete(pt[0].id)
            print "Profile template [%s] deleted." % name
        else:
            print "ERROR: Profile template [%s] not found." % name

    @ensure_arg("profile")
    def do_edit(self, name):
        pt = list(ProfileTemplate.selectBy(name=name))
        if pt:
            pt = pt[0]
            p = pt.profile
            dct = {k:getattr(p,k) for k in p.sqlmeta.columns}
            in_prof = {k:("ny"[v] if type(v) is bool else v) for k,v in dct.iteritems() if v is not None}
            prof = self.ask_profile(name=name, **in_prof)
            pt.name = prof.pop("name")
            for k,v in prof.iteritems():
                setattr(p, k, v)
        else:
            print "ERROR: Profile template [%s] not found." % name

class YubikeyCLI(CLI):
    def __init__(self, options):
        CLI.__init__(self)
        self.options = options
        self.prompt_push("yubikey")

    complete_del = CLI._complete_yubikey

    def do_ls(self, arg):
        for yk in Yubikey.select():
            usage = ("used for key %s" % yk.export.key.name) if yk.export else "not used"
            owner = ("owned by %s" % yk.owner) if yk.owner else "not owned"
            print "%-10s %-18s  %s" % (yk.serial,owner,usage)

    def do_status(self, arg):
        serial,ccid = yubikey_get_serial_and_mode()
        if serial is None:
            print "No yubikey found."
            return
        if ccid:
            o = check_output(["ykneomgr", "--get-mode"])
            mode = int(o,16)
            strmode = "+".join(x for i,x in enumerate(["OTP","CCID", "U2F"]) if (mode+1)&(1<<i))
            if mode & 0x80:
                strmode += " with eject"
            print "Found yubikey with serial [%s] in mode %s" % (serial, strmode)
            check_call(["yubico-piv-tool", "-a", "status"])
        else:
            print "Found yubikey with serial [%s]" % serial
            print "Mode is not CCID. sshpki cannot gather more info."

        yks = list(Yubikey.selectBy(serial=serial))
        if yks:
            print "This yubikey is enrolled in the database:"
            yk = yks[0]
            usage = ("used for key %s" % yk.export.key.name) if yk.export else "not used"
            owner = ("owned by %s" % yk.owner) if yk.owner else "not owned"
            print "%-10s %-18s  %s" % (yk.serial,owner,usage)

    @ensure_arg("yubikey owner")
    def do_enroll(self, owner):
        yubikey_enroll(owner)


    @ensure_arg("serial number")
    def do_del(self, serial):
        y = list(Yubikey.selectBy(serial=serial))
        if len(y) == 0:
            print "yubikey not found"
        else:
            Yubikey.delete(y[0].id)
            print "yubikey deleted"

##  ___  ___
## |   \| _ )
## | |) | _ \
## |___/|___/
##

def create_pki(fname):
    cnx = "sqlite://"+os.path.realpath(fname)
    sqlhub.processConnection=connectionForURI(cnx)
    for tb in [Meta, CA, Key, Cert, Profile, ProfileTemplate,
               FileExport, YubikeyExport, Yubikey]:
        tb.createTable()
    name = raw_input("YUBIKEY SSH PKI name: ")
    Meta(version=DBVERSION, pkiname=name)

def open_pki(fname):
    cnx = "sqlite://"+os.path.realpath(fname)
    sqlhub.processConnection=connectionForURI(cnx)
    m = Meta.select()[0]
    if m.version != DBVERSION:
        raise Exception("bad db version (got %i, expected %i)" % (m.version, DBVERSION))



##  __  __      _
## |  \/  |__ _(_)_ _
## | |\/| / _` | | ' \
## |_|  |_\__,_|_|_||_|
##

def unlink_temp_dir(options):
    shutil.rmtree(options.tmp)

def main():
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument("-C", "--create", action="store_true",
                        help="Create the DB and exit")
    parser.add_argument("-f", "--pki-db", default=os.path.expanduser(DEFAULTDB),
                        help="path to the pki DB file")
    parser.add_argument("--ca_bits", default=4096)
    parser.add_argument("--cert_bits", default=2048)
    parser.add_argument("--keep-temp", action="store_true")

    options = parser.parse_args()

    options.pki = os.path.realpath(options.pki_db)
    if options.create:
        create_pki(options.pki)
    else:
        open_pki(options.pki)

        options.tmp = tempfile.mkdtemp(dir=TMPPATH)
        options.levels = [ ]
        if not options.keep_temp:
            atexit.register(unlink_temp_dir, options)

        cli = MainCLI(options)
        cli.cmdloop_catcherrors()



if __name__ == "__main__":
    main()
