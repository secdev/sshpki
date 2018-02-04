#! /usr/bin/env python


import os
import sys
import re
import shutil
import traceback
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

class Cert(SQLObject):
    ca = ForeignKey("CA")
    key = ForeignKey("Key")
    serial = IntCol(default=-1)
    profile = ForeignKey("Profile")
    cert = StringCol(unique=True)
    start_time = DateTimeCol(default=None)
    end_time = DateTimeCol(default=None)

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

class ProfileTemplate(SQLObject):
    name = UnicodeCol(unique=True)
    profile = ForeignKey("Profile")

class FileExport(SQLObject):
    key = ForeignKey("Key")
    filename = StringCol()

class YubikeyExport(SQLObject):
    key = ForeignKey("Key")
    serial = IntCol()


##  _   _ _   _ _
## | | | | |_(_) |
## | |_| |  _| | |
##  \___/ \__|_|_|
##

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

def pwqgen():
    return check_output("pwqgen").strip()

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
        pwd = pwqgen()
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

def sign_key(options, cert_name, ca, key, profile_template):
    opts = []
    profile = profile_template.profile
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
    for k in YubikeyExport.select():
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
    ca.serial += 1
    key.ca = ca
    certcontent = open(certfile).read()
    cert = Cert(ca=ca, key=key, profile=prof2, serial=1, cert=certcontent)
    if start_time:
        cert.start_time = start_time
    if end_time:
        cert.end_time = end_time
    return cert


def create_CA(options, ca_name):
    k = create_key(options, ca_name, options.ca_bits)
    k.is_ca = True
    # create empty KRL
    with get_tmpfile(options) as krl_file:
        check_call([ "ssh-keygen", "-kf", krl_file.name ])
        krl = krl_file.read()
    ca = CA(name=ca_name, key=k, krl=krl)

def update_krl(options, ca):
    rev = []
    for k in ca.signed:
        if k.revoked:
            kfile = get_tmpfile(options)
            kfile.write(k.pubkey)
            kfile.flush()
            rev.append(kfile.name)
    with get_tmpfile(options) as krl:
        with get_tmpfile(options) as ca_pub:
            ca_pub.write(ca.key.pubkey)
            ca_pub.flush()
            cmd = [ "ssh-keygen", "-kf", krl.name,
                    "-s", ca_pub.name ] + rev
            check_call(cmd)
            shutil.copy(krl.name, "/tmp/krltoto")
        ca.krl = krl.read()

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

    def _complete(self, obj, val):
        matches = obj.select("name like '%s%%'" % val)
        return [o.name for o in matches]

    def _complete_ca(self, text, line, begidx, endidx):
        return self._complete(CA, text)
    def _complete_key(self, text, line, begidx, endidx):
        return self._complete(Key, text)
    def _complete_profiletemplate(self, text, line, begidx, endidx):
        return self._complete(ProfileTemplate, text)



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

class CACLI(CLI):
    def __init__(self, options):
        CLI.__init__(self)
        self.options = options
        self.prompt_push("CA")

    complete_use = CLI._complete_ca
    complete_show = CLI._complete_ca

    def do_ls(self, arg):
        for ca in CA.select():
            print "%-30s %8s  signed %2i keys" % (ca.name,
                                                  "REVOKED" if ca.key.revoked else "active",
                                                  len(ca.signed))

    @ensure_arg("CA")
    def do_add(self, ca_name):
        create_CA(self.options, ca_name)

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
            print cas[0].key.pubkey

class CertCLI(CLI):
    def __init__(self, options):
        CLI.__init__(self)
        self.options = options
        self.prompt_push("certs")

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

    def do_ls(self, arg):
        for k in Key.select():
            ca = "CA" if k.is_ca else "user"
            signed = "" if k.is_ca else (("signed by [%s]" % k.ca.name) if k.ca else "never signed")
            status = "REVOKED" if k.revoked else "ACTIVE" 
            print "%-30s %-4s %-7s  %4i bits  %s" % (k.name, ca, status, k.bits, signed)

    @ensure_arg("key")
    def do_revoke(self, key_name):
        keys = list(Key.selectBy(name=key_name))
        if list(keys) == 0:
            print "Key [%s] not found" % key_name
            return
        key = keys[0]
        if ask("Are you sure you want to revoke key [%s] ? " % key.name, "yn") == "n":
                print "aborted."
                return
        if key.is_ca:
            if ask("Key [%s] is a CA. Are you sure you want to revoke it ? " % key.name, "yn") == "n":
                print "aborted."
                return
        key.revoked = True
        for cert in key.certs:
            update_krl(self.options, cert.ca)

    @ensure_arg("key file")
    def do_import(self, key_file):
        pubkey = open(key_file).read()
        o = check_output(["ssh-keygen", "-lf", key_file])
        bits = int(o.split(" ",1)[0])
        name = rl_input("name: ")
        Key(name=name, bits=bits, pubkey=pubkey)

class UseCLI(CLI):
    def __init__(self, options, ca):
        CLI.__init__(self)
        self.ca = ca
        self.options = options
        self.prompt_push(ca.name)

    complete_sign = CLI._complete_key

    def do_show(self, arg):
        print self.ca.key.pubkey

    @ensure_arg("cert")
    def do_add(self, cert_name):
        key = create_key(self.options, cert_name, self.options.cert_bits)
        proftmpl = get_profile_template(self.options)
        sign_key(self.options, cert_name, self.ca, key, proftmpl)

    @ensure_arg("key")
    def do_sign(self, key_name):
        cert_name = rl_input("Enter cert name: ")
        keys = list(Key.selectBy(name=key_name))
        if len(keys) == 0:
            print "key [%s] not found" % key_name
        else:
            key = keys[0]
            proftmpl = get_profile_template(self.options)
            sign_key(self.options, cert_name, self.ca, key, proftmpl)

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
                print "  -> certificate {cert.serial:>3} {profile} {validity}".format(
                    cert=cert, validity=validity, profile=profile_summary(cert.profile))



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
        tmp = tempfile.mktemp(dir=self.options.tmp)
        shutil.copy(self.privfname, tmp)
        check_call(["ssh-keygen", "-p", "-P", self.pwd,
                    "-f", tmp])
        shutil.copy(tmp, dest)
        self.mark_as_exported()
        os.unlink(tmp)
        FileExport(key=self.key, filename=dest)

    def do_yubikey(self, arg):
        serial = check_output(["ykinfo", "-s"])
        serial = int(serial.split()[1])
        ans = ask("Export to yubikey with serial #%i ?", "yn")
        if ans == "y":
            print "not implemented"

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



##  ___  ___
## |   \| _ )
## | |) | _ \
## |___/|___/
##

def create_pki(fname):
    cnx = "sqlite://"+os.path.realpath(fname)
    sqlhub.processConnection=connectionForURI(cnx)
    for tb in [Meta, CA, Key, Cert, Profile, ProfileTemplate,
               FileExport, YubikeyExport]:
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


def main():
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument("-C", "--create", action="store_true",
                        help="Create the DB and exit")
    parser.add_argument("-f", "--pki-db", default=os.path.expanduser(DEFAULTDB),
                        help="path to the pki DB file")
    parser.add_argument("--ca_bits", default=4096)
    parser.add_argument("--cert_bits", default=2048)

    options = parser.parse_args()

    options.pki = os.path.realpath(options.pki_db)
    if options.create:
        create_pki(options.pki)
    else:
        open_pki(options.pki)

        options.tmp = tempfile.mkdtemp(dir=TMPPATH)
        options.levels = [ ]

        cli = MainCLI(options)
        cli.cmdloop_catcherrors()



if __name__ == "__main__":
    main()
