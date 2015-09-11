
"""
KerbMinder.py

This script refreshes or renews kerberos tickets based on their status. It checks for
domain reachability and connectivity before proceeding. For a renewal, the user is
prompted for their password and allowed only two tries. Two consecutive incorrect
passwords result in a warning dialog. If an incorrect attempt results in a locked
account, the user is informed their account is locked.

If the 'Remember password' box is checked, a correct password is saved to the keychain
and all subsequent renewals use it. Should the password get out of sync with the domain
password (e.g. after the user changes their password), the keychain will automatically
remove the old saved password and the user will be prompted to enter one.

This script is meant to be triggered by a launch agent working in conjunction with a
crankd launch daemon that looks for network state changes.

Last Revised - 7/13/2015
"""

import re, subprocess, sys, syslog, errno
import os, plistlib
import getpass
import Pashua
from SystemConfiguration import SCDynamicStoreCopyConsoleUser

__author__  = 'Peter Bukowinski (pmbuko@gmail.com)'
__version__ = '1.1'



adpassmon_plist = os.path.expanduser('~/Library/Preferences/org.pmbuko.ADPassMon.plist')
path_root = os.path.dirname(os.path.realpath(__file__))
#path_root = '/Library/Application Support/crankd/'
path_user = os.path.expanduser('~/Library/Application Support/crankd')
image_path = path_root + '/KerbMinder_logo.png'

syslog.openlog("KerbMinder")

def setDoNotAsk():
  """
  Sets Do Not Ask Flag
  """

  path = path_user + '/kmfiles/doNotAsk'

  with open(path, 'w') as f:
    f.write("doNotAsk")

  logPrint("User has chosen not to use KerbMinder. Exiting.")
  sys.exit()

def getDoNotAsk():
  """Gets Do Not Ask Flag"""

  path = path_user + '/kmfiles/doNotAsk'

  return True if os.path.exists(path) else False


def checkCreatePath(path):
  if not os.path.exists(path):
    os.makedirs(path)
    logPrint('Creating user path: ' + path)

def logPrint(message, l=True, p=True):
  """Logs a message and prints it to stdout.
  Optionally disable either logging or stdout."""
  if l: syslog.syslog(syslog.LOG_ALERT, message)
  if p: print message


def getUsername():
  """Returns the user associated with the LaunchAgent running KerbMinder.py"""
  return getpass.getuser()


def getConsoleUser():
  """Returns current console user"""
  return SCDynamicStoreCopyConsoleUser(None, None, None)[0]



def usersMatch():
  """Returns True if LaunchAgent owner is logged in to console or LaunchAgent owner's user file exists."""

  path = path_user + '/kmfiles/user'
  if os.path.isfile(path):
    return True 

  return True if getUsername() == getConsoleUser() else False


def getKerbID():
  """Returns the Kerberos ID of the current user by searching directory services. If no
  KID is found, either the search path is incorrect or the domain is not accessible."""
  uPath = '/Users/' + getConsoleUser()
  userpath = path_user + '/kmfiles/user'
  domainpath = path_root + '/kmfiles/domain'

  dsclSearch = subprocess.Popen(['dscl','/Search','read',uPath,'AuthenticationAuthority'],
                                stderr=subprocess.STDOUT,
                                stdout=subprocess.PIPE).communicate()[0]
  match = re.search(r'[a-zA-Z0-9+_\-\.]+@[^;]+\.[A-Z]{2,}', dsclSearch, re.IGNORECASE)
  match = match.group()
  logPrint('Found KID from AD: ' + match)
  match = ""

  if not match:
    if os.path.isfile(userpath) and os.path.isfile(domainpath):
      match = userFromKID() + '@' + domainFromKID()
    elif not getDoNotAsk():
      logPrint('No Kerberos Principal found in DS search path. Asking user.')
      match, doNotAsk = loginDialog() 
      if getDoNotAsk():
        setDoNotAsk()
    else:
      logPrint('No Kerberos Principal found in DS search path. doNotAsk is set. Delete ' + path_user + '/kmfiles/doNotAsk to reset.' )
      sys.exit()

  logPrint('Kerberos Principal is ' + match)
  
  return match


def domainFromKID(kid = None):
  """Returns the domain name by chopping off the 'username@' portion of the Kerb ID. Also
  writes domain name to file for use when not on domain."""
  path = path_root + '/kmfiles/domain'
  try:
    domain = kid.split('@')[1]
    with open(path, 'w') as f:
      f.write(domain)
  except:
    with open(path, 'r') as f:
      domain = f.read()

  return domain.upper()

def userFromKID(kid = None):
  """Returns the username by chopping off the '@REALM' portion of the Kerb ID. Also
  writes username to file."""
  path = path_user + '/kmfiles/user'

  user = ""

  if kid:
    user = kid.split('@')[0]

  if not os.path.isfile(path):
    if getUsername() == getConsoleUser():
      user = getUsername()

  if user:
    try:
      with open(path, 'w') as f:
        f.write(user)
    except e:
      raise e
  else:
    try:
      with open(path, 'r') as f:
        user = f.read()
    except e:
      raise e
  print user
  return user

def ticketCheck(kid):
  """Checks for kerberos ticket presence and either calls refresh or renew depending on
  ticket status."""
  klistResponse = subprocess.call(['klist', '--test'])
  if klistResponse == 0:
    if not refreshTicket():
      renewTicket(kid)
  else:
    renewTicket(kid)


def refreshTicket():
  """Refreshes an existing ticket."""
  mRefreshed = 'Ticket refreshed.'
  mFailed =    'Ticket refresh failed. Renewing...'
  logPrint('Ticket found.')
  try:
    refresh = subprocess.check_output(['kinit', '--renew'])
    if not refresh:
      logPrint(mRefreshed)
      return True

    else:
      logPrint(mFailed)
      return False

  except:
    logPrint(mFailed)
    return False


def renewTicket(kid):
  """Renews or acquires a ticket, using Pashua password prompt if necessary."""
  mRenewed = 'Ticket renewed.'
  mWrong =   'Password incorrect. Trying again.'
  m2Wrong =  'Password incorrect again. Giving up to prevent lockout.'
  mLocked =  'Domain account locked out.'
  mWrongUsername = 'Login incorrect. Asking user'
  logPrint('Ticket expired or not found.')

  if not checkKeychain(kid):
    password, save = passDialog(kid)
    renew = kinitCommand(password)
    logPrint("renewTicket() " + renew)
    if 'incorrect' in renew:
      logPrint(mWrong)
      password, save  = passDialog(kid, True)
      renew = kinitCommand(password)
      if 'incorrect' in renew:
        logPrint(m2Wrong)
        displayWarning()
      elif 'revoked' in renew:
        logPrint(mLocked)
        displayLockout()
      else:
        if save == '1': passToKeychain(kid, password)
        logPrint(mRenewed)
    elif 'revoked' in renew:
      logPrint(mLocked)
      displayLockout()
    elif 'unknown' in renew:
      logPrint(mWrongUsername)
      login = loginDialog()
      renewTicket(login)
    else:
      if save == '1': passToKeychain(kid, password)
      logPrint(mRenewed)

  else:
    kinitKeychainCommand(kid)
    logPrint(mRenewed)

def loginDialog(image = image_path):
  """Displays login and password prompt using Pashua. Returns login and password as string and save checkbox
  state as 0 or 1."""

  message = 'Computer is not bound to AD. Enter your Kerberos credentials:'

  # Dialog config
  conf = '''
  # Window
  *.title = Kerberos Ticket Creation
  *.floating = 1

  # Image/logo
  img.type = image
  img.path = %s
  img.maxwidth = 64
  img.border = 0
  img.x = 0
  img.y = 110

  # Message
  msg.type = text
  msg.text = %s
  msg.x = 80
  msg.y = 130
  
  # Login Message
  loginmsg.type = text
  loginmsg.text = Login: 
  loginmsg.x = 80
  loginmsg.y = 100

  # Login field
  login.type = textfield
  login.default = login@REALM.COM
  login.mandatory = 1
  login.width = 280
  login.x = 82
  login.y = 70

  # Do not ask again checkbox
  dna.type = button
  dna.label = Do not use KerbMinder

  # Default button
  db.type = defaultbutton
  db.label = OK

  # Cancel button
  cb.type = cancelbutton
  cb.label = Cancel
  ''' % (image,message)

  # Open dialog and get input
  dialog = Pashua.run(conf)

  # Check for Cancel before return
  if dialog['cb'] == '1':
    logPrint('User canceled.')
    sys.exit(0)

  if dialog['dna'] == '1':
    setDoNotAsk()

  return dialog['login']

def passDialog(kid, retry = False, image = image_path):
  """Displays password prompt using Pashua. Returns password as string and save checkbox
  state as 0 or 1."""

  message = 'Ticket for %s expired. Enter your password to renew:' % kid
  if retry: message = 'Your password was incorrect. Please try again:'

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

  # Default button
  db.type = defaultbutton
  db.label = OK

  # Cancel button
  cb.type = cancelbutton
  cb.label = Cancel
  ''' % (image,message)

  # Open dialog and get input
  dialog = Pashua.run(conf)

  # Check for Cancel before return
  if dialog['cb'] == '1':
    logPrint('User canceled.')
    sys.exit(0)

  return dialog['psw'], dialog['save']


def kinitCommand(password):
  """Runs the kinit command with supplied password."""
  renew1 = subprocess.Popen(['echo',password], stdout=subprocess.PIPE)
  print password,userFromKID()+'@'+domainFromKID()
  print 'kinit','-l','10h','--renewable','--password-file=STDIN',userFromKID()+'@'+domainFromKID()
  renew2 = subprocess.Popen(['kinit','-l','10h','--renewable','--password-file=STDIN',userFromKID()+'@'+domainFromKID()],
                            stderr=subprocess.PIPE,
                            stdin=renew1.stdout,
                            stdout=subprocess.PIPE)
  renew1.stdout.close()

  return renew2.communicate()[1]

def kinitKeychainCommand(kid):
  """Runs the kinit command with keychain password."""
  """exception most likely means a password mismatch,
  so we should run renewTicket again."""
  kinitKeychain = subprocess.Popen(['kinit', '-l', '10h', '--renewable',getConsoleUser()+'@'+domainFromKID()])

  returncode = kinitKeychain.poll()

  while returncode is None:

    returncode = kinitKeychain.poll()
    data = kinitKeychain.communicate()[0]
    if data is None:
      continue
    if "Password:" in data: 
      logPrint("kinitKeychainCommand: " + str(data))
      kinitKeychain.terminate()
      renewTicket(kid)
    elif "unknown" in data:
      logPrint("merde")

  if returncode == 0:
    return 0
  else:
        logPrint("kinitKeychainCommand: RETURNCODE=" + str(returncode))
        renewTicket(kid)


def checkKeychain(kid):
  """Checks keychain for kerberos entry."""
  user = getConsoleUser()
  principal = userFromKID(kid)
  domain = domainFromKID(kid)
  try:
    subprocess.check_output(['security', 'find-generic-password',
                             '-a', user,
                             '-l', domain + ' (' + principal + ')',
                             '-s', domain,
                             '-c', 'aapl'])
    logPrint('Keychain entry found.')
    return True

  except:
    logPrint('Keychain entry not found.')
    return False


def passToKeychain(kid, password):
  """Saves password to keychain for use by kinit."""
  user = getConsoleUser()
  principal = userFromKID(kid)
  domain = domainFromKID(kid)
  try:
    subprocess.check_output(['security', 'add-generic-password',
                             '-a', user,
                             '-l', domain + ' (' + user + ')',
                             '-s', domain,
                             '-c', 'aapl',
                             '-T', '/usr/bin/kinit',
                             '-w', str(password)])
    logPrint('Added password to keychain.')

  except:
    logPrint('Failed adding password to keychain.')


def displayWarning():
  """Displays double incorrect password warning."""
  warning = subprocess.check_output(['osascript', '-e',
    'display dialog "Your password was incorrect again. To prevent account lockout you will not be asked again until the next time you reconnect." with title "Incorrect Password" with icon 2 buttons {"OK"} default button 1'])
  sys.exit(0)


def displayLockout():
  """Displays lockout warning."""
  warning = subprocess.check_output(['osascript', '-e',
    'display dialog "Your domain account was locked out due to too many incorrect password attempts." with title "Account Locked" with icon 2 buttons {"OK"} default button 1'])
  sys.exit(0)


def domainPingCheck(domain):
  """Tries to ping the domain. This won't work at all sites since it simply tries to ping
  the part of the kerberos ID after the @."""
  pingResponse = subprocess.call(['ping', '-c', '3', domain])
  if not pingResponse == 0:
    logPrint(domain + ' is not accessible. Exiting.')
    sys.exit(0)
  logPrint(domain + ' is accessible.')

  return True


def domainDigCheck(domain):
  """Checks if AD domain is accessible by looking for SRV records for LDAP in DNS."""
  dig = subprocess.check_output(['dig', '-t', 'srv', '_ldap._tcp.'+domain])
  if not 'ANSWER SECTION' in dig:
    logPrint('Domain not accessible. Exiting.')
    sys.exit(0)
  logPrint('Domain is accessible.')
  return True


def enabledByPlist():
  """Checks ADPassMon plist to see if KerbMinder is enabled. If plist does not exist,
  returns True."""
  try:
    if not os.path.isfile(adpassmon_plist):
      return True

    # had errors reading binary plist - not sure why? - so added conversion
    subprocess.call(['plutil','-convert','xml1',adpassmon_plist])
    d = plistlib.readPlist(adpassmon_plist)
    enabled = d['enableKerbMinder']
    if not enabled:
      return False

  except:
    return True

  return True


def main():
  """Start me up"""
  checkCreatePath(path_user + '/kmfiles')

  if enabledByPlist() and usersMatch():
    kid = getKerbID()
    user = userFromKID(kid)
    domain = domainFromKID(kid)
    if domainDigCheck(domain):
      ticketCheck(kid)
    sys.exit(0)


if __name__ == '__main__':
  main()
