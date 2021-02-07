#
# Copyright (C) 2010 Roberto Leandrini <anaconda@ditalinux.it>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#

__module_name__ = 'cap_sasl'
__module_version__ = '0.5'
__module_description__ = 'SASL authentication plugin'
__module_author__ = 'Roberto Leandrini <anaconda@ditalinux.it>'

import base64
import ConfigParser
import os

import xchat

conf = ConfigParser.SafeConfigParser()
conffileName = xchat.get_info('xchatdir') + os.sep + 'sasl.conf'
# cwd is different for cb functions :/
# conf.read([conffileName, 'sasl.conf'])
saslTimers = {}

def connected_cb(word, word_eol, userdata):
	# Ask the server for the list of supported capabilities
	conf.read(conffileName)
	if not conf.has_section(xchat.get_info('network')):
		return

	xchat.command('CAP LS')
	return xchat.EAT_NONE

def sasl_timeout_cb(userdata):
    # Tell the server we've finished playing with capabilities if SASL times out
    xchat.command('CAP END')
    return xchat.EAT_NONE

def cap_cb(word, word_eol, userdata):
    subcmd = word[3]
    caps = word[4:]
    caps[0] = caps[0][1:]
    if subcmd == 'LS':
        toSet = []
        # Parse the list of capabilities received from the server
        if 'multi-prefix' in caps:
            toSet.append('multi-prefix')
        # Ask for the SASL capability only if there is a configuration for this network
        if 'sasl' in caps and conf.has_section(xchat.get_info('network')):
            toSet.append('sasl')
        if toSet:
            # Actually set capabilities
            xchat.command('CAP REQ :%s' % ' '.join(toSet))
        else:
            # Sorry, nothing useful found, or we don't support these
            xchat.command('CAP END')
    elif subcmd == 'ACK':
        if 'sasl' in caps:
            xchat.command('AUTHENTICATE PLAIN')
            print("SASL authenticating")
            saslTimers[xchat.get_info('network')] = xchat.hook_timer(5000, sasl_timeout_cb) # Timeout after 5 seconds
            # In this case CAP END is delayed until authentication ends
        else:
            xchat.command('CAP END')
    elif subcmd == 'NAK':
        xchat.command('CAP END')
    elif subcmd == 'LIST':
        if not caps:
            caps = 'none'
        print('CAP(s) currently enabled: %s') % ', '.join(caps)
    return xchat.EAT_XCHAT

def authenticate_cb(word, word_eol, userdata):
    nick = conf.get(xchat.get_info('network'), 'nick')
    passwd = conf.get(xchat.get_info('network'), 'password')
    authStr = base64.b64encode('\0'.join((nick, nick, passwd)))
    if not len(authStr):
        xchat.command('AUTHENTICATE +')
    else:
        while len(authStr) >= 400:
            toSend = authStr[:400]
            authStr = authStr[400:]
            xchat.command('AUTHENTICATE %s' % toSend)
        if len(authStr):
            # Send last part
            xchat.command('AUTHENTICATE %s' % authStr)
        else:
            # Last part was exactly 400 bytes, inform the server that there's nothing more
            xchat.command('AUTHENTICATE +')
    return xchat.EAT_XCHAT

def sasl_90x_cb(word, word_eol, userdata):
    # Remove timer
    xchat.unhook(saslTimers[xchat.get_info('network')])
    xchat.command('CAP END')
    return xchat.EAT_NONE

def sasl_cb(word, word_eol, userdata):
    if len(word) < 3:
        print('Usage: /SASL <-set|-unset> <network> [<nick> <password>]')
    else:
        subcmd = word[1]
        network = word[2]
        if subcmd == '-set':
            # -set needs also a nick and its password
            if len(word) < 5:
                print('Usage: /SASL -set <network> <nick> <password>')
            else:
                nick = word[3]
                passwd = word[4]
                if not conf.has_section(network):
                    conf.add_section(network)
                    what = 'Added'
                else:
                    what = 'Updated'
                conf.set(network, 'nick', nick)
                conf.set(network, 'password', passwd)
                # This parameter is currently unused, but reserved for a future version.
                # Currently, PLAIN is the only supported mechanism.
                conf.set(network, 'mechanism', 'PLAIN')
                # Save settings
                conffile = open(conffileName, 'w')
                print(os.getcwd())
                conf.write(conffile)
                conffile.close()
                print('%s SASL settings for network %s') % (what, network)
        elif subcmd == '-unset':
            if conf.remove_section(network): # Returns True if section existed
                # Write on disk only if configuration is actually changed
                conffile = open(conffileName, 'w')
                conf.write(conffile)
                conffile.close()
                print('Successfully removed SASL settings for network ' + network)
            else:
                print('SASL authentication is not configured for network ' + network)
        else:
            print('Usage: /SASL <-set|-unset> <network> [<nick> <password>]')
    return xchat.EAT_NONE

xchat.hook_print('Connected', connected_cb)

xchat.hook_server('AUTHENTICATE', authenticate_cb)
xchat.hook_server('CAP', cap_cb)
xchat.hook_server('903', sasl_90x_cb) # RPL_SASLSUCCESS
xchat.hook_server('904', sasl_90x_cb) # ERR_SASLFAIL
xchat.hook_server('905', sasl_90x_cb) # ERR_SASLTOOLONG
xchat.hook_server('906', sasl_90x_cb) # ERR_SASLABORTED
xchat.hook_server('907', sasl_90x_cb) # ERR_SASLALREADY

xchat.hook_command('SASL', sasl_cb, help = 'Usage: /SASL <-set|-unset> <network> [<nick> <password>], ' +
                   'set or unset SASL authentication for an IRC network. Arguments <nick> and <password> are optional for -unset')
