# -*- coding: utf-8 -*-
import sys
import subprocess
import getpass
import syslog
import re
import os
import Pashua

__author__ = 'fti'

path_root = os.path.dirname(os.path.realpath(__file__))
image_path = '/Library/Actelion/actelion_logo.png'


# image_path = path_root + '/KerbMinder_logo.png'

class WrongPasswordError(Exception):
    pass

class WrongUsernameError(Exception):
    pass

class RevokedError(Exception):
    pass


def get_current_username():
    """Returns the user associated with the LaunchAgent running KerbMinder.py"""
    return getpass.getuser()


def log_print(message, l=True, p=True):
    """Logs a message and prints it to stdout.
    Optionally disable either logging or stdout.
    """
    if l:
        syslog.syslog(syslog.LOG_ALERT, message)
    if p:
        print message


def domain_dig_check(domain):
    """Checks if AD domain is accessible by looking for SRV records for LDAP in DNS.
    Returns True if it can ping the domain, otherwise exits.
    """
    dig = subprocess.check_output(['dig', '-t', 'srv', '_ldap._tcp.' + domain])
    if 'ANSWER SECTION' not in dig:
        log_print('Domain not accessible. Exiting.')
        sys.exit(0)
    log_print('Domain is accessible.')
    return True


def login_dialog(image=image_path):
    """Displays login and password prompt using Pashua. Returns login as string."""

    message = 'Computer is not bound to AD. Enter your Kerberos credentials:'

    # Dialog config
    conf = '''
    # Window
    *.title = Kerberos Ticket Creation
    *.floating = 1

    # Image/logo
    img.type = image
    img.path = %s
    #img.maxwidth = 64
    img.border = 0
    #img.x = 00
    #img.y = 200

    # Message
    msg.type = text
    msg.text = %s
    #msg.x = 80
    #msg.y = 150

    ## Login Message
    #loginmsg.type = text
    #loginmsg.text = Login:
    ##loginmsg.x = 80
    ##loginmsg.y = 130

    # Login field
    login.type = textfield
    login.label = Login:
    login.default = login
    login.mandatory = 1
    #login.width = 200
    #login.x = 82
    #login.y = 100


    ## Realm Message
    #realmmsg.type = text
    #realmmsg.text = Domain:
    ##realmmsg.x = 200
    ##realmmsg.y = 130

    # Add a popup menu
    realm.type = popup
    #realm.width = 200
    realm.label = Domain:
    #realm.x = 200
    #realm.y = 100
    realm.option = EUROPE.ACTELION.COM
    realm.option = AMERICA.ACTELION.COM
    realm.option = ASIA.ACTELION.COM

    ## Do not ask again checkbox
    #dna.type = button
    #dna.label = Do not use KerbMinder

    # Default button
    db.type = defaultbutton
    db.label = OK
    db.x = 0
    db.y = 50

    # Cancel button
    cb.type = cancelbutton
    cb.label = Cancel
    ''' % (image, message)

    # Open dialog and get input
    dialog = Pashua.run(conf)

    # Check for Cancel before return
    if dialog['cb'] == '1':
        log_print('User canceled.')
        sys.exit(0)

    return dialog['login'] + '@' + dialog['realm']


def pass_dialog(kid, retry=False, image=image_path):
    """Displays password prompt using Pashua. Returns password as string and save checkbox state as 0 or 1.

    :returns: (string password, int save)
    :param kid: The full principal name (login@REALM) 
    :param retry: Change the prompt to ask to try again
    :param image: Path to logo
    """

    message = 'Ticket for %s expired. Enter your password to renew:' % kid
    if retry:
        message = 'Your password was incorrect. Please try again:'

    # Dialog config
    conf = '''
    # Window
    *.title = Kerberos Ticket Renewal
    *.floating = 1

    # Image/logo
    img.type = image
    img.path = %s
    img.maxwidth = 64
    img.border = 0
    img.x = 0
    img.y = 100

    # Message
    msg.type = text
    msg.text = %s
    msg.x = 80
    msg.y = 110

    # Password field
    psw.type = password
    psw.mandatory = 1
    psw.width = 280
    psw.x = 82
    psw.y = 70

    # Save checkbox
    save.type = checkbox
    save.label = Remember this password in my keychain
    save.x = 80
    save.y = 45
    save.default = 1

    # Default button
    db.type = defaultbutton
    db.label = OK

    # Cancel button
    cb.type = cancelbutton
    cb.label = Cancel
    ''' % (image, message)

    # Open dialog and get input
    dialog = Pashua.run(conf)

    # Check for Cancel before return
    if dialog['cb'] == '1':
        log_print('User canceled.')
        sys.exit(0)

    return dialog['psw'], dialog['save']

def display_lockout():
  """Displays lockout warning."""
  subprocess.check_output(['osascript', '-e',
    'display dialog "Your domain account was locked out due to too many incorrect password attempts." with title "Account Locked" with icon 2 buttons {"OK"} default button 1'])
  sys.exit(1)

def todo(message):
    log_print("TODO: " + message)


class Principal(object):
    def __init__(self):
        self.path = path_root + '/kmfiles/principal.txt'
        self.principal = ""

        try:
            self.principal = self.get_from_ad()
        except (subprocess.CalledProcessError, ValueError):
            self.principal = self.get_from_user()

    def __str__(self):
        return self.principal

    @staticmethod
    def get_from_ad():
        """Returns the Kerberos ID of the current user by searching directory services. If no
        KID is found, either the search path is incorrect or the domain is not accessible."""

        user_path = '/Users/' + get_current_username()

        try:
            output = subprocess.check_output(['dsconfigad', '-show'])
            log_print(output)
            if "Active Directory" in output:
                pass
            else:
                raise ValueError("Computer is not bound.")

            output = subprocess.check_output(['dscl',
                                              '/Search',
                                              'read',
                                              user_path,
                                              'AuthenticationAuthority'],
                                             stderr=subprocess.STDOUT)
            match = re.search(r'[a-zA-Z0-9+_\-\.]+@[^;]+\.[A-Z]{2,}', output, re.IGNORECASE)
            match = match.group()
            log_print('Kerberos Principal is ' + match)
            return match

        except (subprocess.CalledProcessError, ValueError) as e:
            log_print("Can't find Principal from AD: " + str(e))
            raise

    def get_from_user(self):

        try:
            principal = self.read()
            if principal:
                log_print("Found principal from cache: " + principal)
                return principal
        except(IOError, ValueError):
            log_print("Principal is not cached, asking user…")
            self.principal = login_dialog()

            try:
                self.write()
            except IOError as e:
                log_print("Cannot write principal: " + str(e))

        log_print("Principal is: " + str(self))
        return str(self)

    def exists(self):
        if self.principal:
            return True
        else:
            return False

    def get_user_id(self):
        return self.principal.split('@')[0]

    def get_realm(self):
        return self.principal.split('@')[1]

    def write(self):
        try:
            with open(self.path, 'w') as f:
                f.write(self.principal)
        except:
            print "Unexpected error:", sys.exc_info()[0]
            raise

    def read(self):
        try:
            with open(self.path, 'r') as f:
                principal = f.read()
            if principal:
                return principal
            else:
                raise ValueError("Cannot read principal from cache")
        except (IOError, ValueError) as e:
            log_print("Warning: " + str(e))
            raise

    def delete(self):
        """Deletes cache file and removes from memory"""
        try:
            os.remove(self.path)
        except OSError as e:
            log_print("Error deleting principal cache: " + str(e))
            raise

        self.principal = None

class Keychain(object):
    def __init__(self):
        pass

    @staticmethod
    def exists(principal):
        """Checks keychain for kerberos entry."""

        user_id = principal.get_user_id()
        realm = principal.get_realm()

        try:
            subprocess.check_output(['security',
                                     'find-generic-password',
                                     '-a', user_id,
                                     '-l', realm + ' (' + user_id + ')',
                                     '-s', realm,
                                     '-c', 'aapl'],
                                    stderr=subprocess.STDOUT)
            log_print('Keychain entry found.')
            return True
        except subprocess.CalledProcessError:
            return False

    @staticmethod
    def store(principal, password):
        """Saves password to keychain for use by kinit. We don't use the flag -U (update) because it prompts the user to
        authorize the security process. Instead, it's safer to delete and store.
        """

        user_id = principal.get_user_id()
        realm = principal.get_realm()

        try:
            subprocess.check_output(['security',
                                     'add-generic-password',
                                     '-a', user_id,
                                     '-l', realm + ' (' + user_id + ')',
                                     '-s', realm,
                                     '-c', 'aapl',
                                     '-j', 'KerbMinder',
                                     '-T', '/usr/bin/kinit',
                                     '-w', str(password)])
            log_print('Added password to keychain.')
            return True

        except subprocess.CalledProcessError as e:
            log_print('Failed adding password to keychain: ' + str(e))
            return False

    @staticmethod
    def delete(principal):
        """Saves password to keychain for use by kinit."""

        user_id = principal.get_user_id()
        realm = principal.get_realm()

        try:
            subprocess.check_output(['security',
                                     'delete-generic-password',
                                     '-a', user_id,
                                     '-s', realm,
                                     '-c', 'aapl'],
                                    stderr=subprocess.STDOUT)
            log_print('Deleted Keychain entry.')
            return True

        except subprocess.CalledProcessError as e:
            log_print('Failed to delete keychain entry: ' + str(e))
            return False


class Ticket(object):
    def __init__(self):
        pass

    @staticmethod
    def is_present():
        """
        Checks for kerberos ticket presence and either calls refresh or renew depending on
            ticket status.
        """
        try:
            subprocess.check_call(['klist', '--test'])
            log_print("Ticket is present.")
            return True
        except subprocess.CalledProcessError:
            log_print("Ticket is not present.")
            return False

    @staticmethod
    def refresh(_principal):
        try:
            log_print("Refreshing Ticket…")
            domain_dig_check(_principal.get_realm())
            subprocess.check_output(['kinit', '--renew'])
            log_print("Refreshed Ticket.")
            return True
        except subprocess.CalledProcessError:
            log_print("Can't refresh ticket.")
            return False

    @staticmethod
    def init(principal):
        log_print('Initiating ticket')
        try:
            domain_dig_check(principal.get_realm())
            subprocess.check_output(['kinit',
                                     '-l',
                                     '10h',
                                     '--renewable',
                                     str(principal)]
                                    )
            log_print("Ticket initiation OK")
            return True
        except subprocess.CalledProcessError as e:
            log_print("Error initiating ticket: " + str(e))
            raise

    @staticmethod
    def init_password(principal, keychain, retry=False):
        """Asks user the password, runs the kinit command, then saves it if command was sucessful and user asked to
        save to keychain."""
        log_print('Initiating ticket with password')
        (password, save) = pass_dialog(principal, retry)

        try:
            domain_dig_check(principal.get_realm())

            renew1 = subprocess.Popen(['echo', password], stdout=subprocess.PIPE)
            renew2 = subprocess.Popen(['kinit',
                                       '-l', '10h',
                                       '--renewable',
                                       '--password-file=STDIN',
                                       str(principal)],
                                      stderr=subprocess.PIPE,
                                      stdin=renew1.stdout,
                                      stdout=subprocess.PIPE)
            renew1.stdout.close()
            out = renew2.communicate()[1]

            if "incorrect" in out:
                raise WrongPasswordError("Wrong password")

            if "revoked" in out:
                raise RevokedError("Domain account locked out.")

            if "unknown" in out:
                raise WrongUsernameError()

            if save == "1":
                keychain.store(principal, password)

            log_print("Ticket initiation OK")
            return True

        except (subprocess.CalledProcessError, WrongPasswordError, RevokedError, WrongUsernameError) as e:
            log_print("Error initiating ticket: " + str(e))
            raise


def main():
    ticket = Ticket()
    principal = Principal()
    keychain = Keychain()

    if ticket.is_present():
        ticket.refresh(principal)
    else:
        if principal.exists():
            if keychain.exists(principal):
                try:
                    ticket.init(principal)
                except (subprocess.CalledProcessError, ValueError):
                    log_print('Error Initiating Kerberos')
            else:
                retry = False
                while True:
                    try:
                        ticket.init_password(principal, keychain, retry)
                    except WrongPasswordError:
                        if retry == False:
                            retry = True
                            log_print("Password mismatch")
                            continue
                        else:
                            log_print("Twice a password error. Exiting.")
                            sys.exit(1)

                    except RevokedError:
                        log_print("Ticket is revoked. Exiting.")
                        display_lockout()
                        sys.exit(1)

                    except WrongUsernameError:
                        log_print("Wrong Username")
                        principal.delete()
                        principal.get_from_user ()
                        continue


                    break
        else:
            try:
                principal.read()
            except(IOError, ValueError):
                todo("Ask for Principal")

            ticket.init(principal)


if __name__ == '__main__':
    main()
