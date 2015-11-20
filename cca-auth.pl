#!/usr/bin/perl
#
# cca-login.pl: A script to log in to Cisco Clean Access with UCI Resnet
# Useful in cron jobs for the required weekly login
#
# Copyright (c) 2005-2008 J. Joe Feise (jfeise at feise dot com).
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
# You can also view the GNU General Public License on the
# World Wide Web at http://www.gnu.org/copyleft/gpl.html

# Revision history

# 1.0.8_TDU - 2014-Oct-9
# Revised by Tahiro Hashizume
# Modified for use by students at Tokyo Denki University.
# Added a section to self-obtain the assigned IP address.

# 1.0.8 - 2012-Mar-19
# Revised by Brian Norris
# Modified POST parameters again (especially 'provider') and used new server hostname
# instead of IP, because (1) the server moved to 'resnet-cca2-arc' and (2) the new
# server's IP is not registered on its certificate ; we must use the hostname

# 1.0.7 - 2008-Oct-12
# Revised by Sameer Patil
# Modified POST parameters for new CCA version after IP address change to 169.234. range

# 1.0.6  - 2007-Aug-28
# Modified POST parameters for apparent new CCA version.

# 1.0.5  - 2006-Sep-27
# Modified the license to GPLv2 only.

# 1.0.4  - 2006-Aug-12
# Added support for the use of a proxy server capable of gatewaying
# SSL requests (e.g., Squid 3.0Pre4.)
# This works around the new OS detection in CCA, which uses the TCP fingerprint
# to determine the OS. Proxying the request through a *nix-based server fools
# the OS detection.
# Also, changed some of the POST fields to match what the original login
# page sends.
#
# 1.0.3  - 2005-Sep-22
# Now using the IP address to connect instead of the DNS name
# This avoids the script hanging if the DNS server is not reachable
#
# 1.0.2  - 2005-Sep-17
# Added option (-a) to change the User Agent string so that Resnet will notice
# it when they look at their logs.
# Added www.uci.edu as original request URI.
#
# 1.0.1  - 2005-Sep-13
# Added verbose option (-v) to print complete result from server.
#
# 1.0    - 2005-Sep-11
# Initial release.

use strict;
use LWP 5.64;
use HTTP::Request::Common;
use LWP::UserAgent;
use vars qw($opt_h $opt_v $opt_a $opt_i $opt_u $opt_p $opt_x);
use Getopt::Std;

print "1.0.8_TDU: Logging in to Cisco Clean Access for TDU users.\n";
print "Copyright (c) 2014 T. Hashizume \n";
print "This script is based on the work by J. Joe Feise. See below;\n\n";
print "1.0.8: Logging in to Cisco Clean Access with UCI Resnet.\n";
print "Copyright (c) 2005-2008 J. Joe Feise (jfeise at feise dot com.)\n";
print "Released under the GNU General Public License version 2.\n\n";

getopts('havx:u:p:');
if ($opt_h || !$opt_u || !$opt_p) {
    # print help text when -h or missing args
    print_help();
    exit(0);
}

my $goterr = 0;  # make sure we clear the error flag

#==============================================================================#
#====================Newly Added on 1.0.8_TDU (From here)======================#
#==============================================================================#
# urlを指定する
my $url = 'https://auth-nac1.ntwk.dendai.ac.jp/auth/perfigo_weblogin.jsp';

# Use Chrome/37.0.2062.124 on Windows 7 as User Agent string
my $user_agent = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36";

# LWPを使ってサイトにアクセスし、HTMLの内容を取得する
my $ua = LWP::UserAgent->new('agent' => $user_agent);
my $res = $ua->get($url);
my $content = $res->content;


my $opt_i = '';
if ($content =~ m#name="userip" value="(.*?)"#) {
    $opt_i = $1;
}

#==============================================================================#
#====================Newly Added on 1.0.8_TDU (Till here)======================#
#==============================================================================#

my ($code, $desc, $headers, $body) = do_post($opt_i, $opt_u, $opt_p, $opt_a, $opt_x);
if ($opt_v) {
    print "Your IP address is $opt_i .\n";
    print "Result Headers\n--------------\n";
    print "HTTP/1.1 $code $desc\n";
    print "$headers\n";
    print "Result Body\n-----------\n";
    print "$body\n";
}
$goterr |= HTTP::Status::is_error($code);
exit($goterr);


sub print_help {
    print <<"HELP";
Usage: $0 [-h] [-a] [-x proxy-URL] -u <User ID> -p <Password>

 -h            - this help
 -v            - verbose
 -a            - Use special User-Agent string to convey the message
                 that CCA is evil.
 -x proxy-URL  - Connect through a proxy server that is able to gateway SSL requests
                 (e.g., Squid 3.0, http://www.squid-cache.org/) to bypass the latest
                 OS detection method.
 -i <IP address> - The IP address of your computer.
 -u <User ID>   - Your User ID.
 -p <Password>   - Your password.

-i, -u, and -p are mandatory parameters.

Examples:  $0 -v -u 12ej999 -p PASSWORD
           $0 -v -x https://192.0.2.234:3129/ -u 12ej999 -p PASSWORD

HELP
}


sub do_post() {
    my ($ip, $username, $pwd, $agent, $proxy) = @_;

    # Create a User Agent object
    my $ua = LWP::UserAgent->new;
    if ($agent) {
        # Let Resnet know that CCA sucks
        $ua->agent("CCA is evil and results in network problems");
    } else {
        $ua->agent($user_agent);
    }
    if ($proxy) {
        # Use a proxy server
        $ua->proxy('https', $proxy);
    }

    # Ask the User Agent object to post to the CCA authentication URL.
    # URL:  https://auth-nac1.ntwk.dendai.ac.jp/auth/perfigo_cm_validate.jsp
    #       (changed with 1.0.8)
    #       IP Address: 169.234.64.122 (* cannot connect securely without
    #                                     using the hostname)
    # POST parameters:
    # reqFrom: perfigo_login.jsp (seems to be fixed, apparently the original URL
    #   of the login form, changed with 1.0.6)
    # uri: the original request URI (can be empty, now set to www.uci.edu)
    # cm: unknown (can be empty, with 1.0.4 contains ws32vklm,
    #              back to empty in 1.0.6, back to ws32vklm in 1.0.7, and back
    #              to empty in 1.0.8)
    # userip: the IP address of the user machine
    # os: ALL (seems to be fixed, with 1.0.4 removed)
    # session: (new with 1.0.4 seems to be empty)
    # pm: Browser platform (new with 1.0.4, originally filled using Javascript,
    #   we use 'Linux i686')
    # index: 0 (seems to be fixed, changed with 1.0.7, changed again with 1.0.8)
    # compact: false (new with 1.0.7)
    # registerGuest: NO (new with 1.0.7)
    # userNameLabel: UCINet ID (content of the label in front of the username
    #   edit field, new with 1.0.7)
    # passwordLabel: Password (content of the label in front of the password
    #   edit field, new with 1.0.7)
    # guestUserNameLabel: Guest ID (content of the label in front of the guest
    #   name edit field, new with 1.0.7)
    # guestPasswordLabel: Password (content of the label in front of the guest
    #   password edit field, new with 1.0.7)
    # username: the user's UCINetID
    # password: the user's password
    # provider: UCInetID Login (changed with 1.0.8) (for guests, there also is a
    #   'Local DB' value with username/password guest in the original form, but
    #   that doesn't seem to be active at this point)
    # submit: Continue (fixed, the name of the submit button, the button parameter
    #   changed with 1.0.7)
    # helpButton: Help (fixed, the name of the help button)
    #
    # Results go into the response object (HTTP::Response).
    my $response = $ua->request(POST 'https://auth-nac1.ntwk.dendai.ac.jp/auth/perfigo_cm_validate.jsp',
                                [reqFrom => 'perfigo_login.jsp',
                                uri => 'http://web.dendai.ac.jp/',
                                cm => 'ws32vklm',
                                userip => $ip,
                                session => '',
                                pm => 'Linux i686',
                                index => '2',
                                pageid => '-1',
                                compact => 'false',
                                registerGuest => 'NO',
                                userNameLabel => 'UserID',
                                passwordLabel => 'Password',
                                guestUserNameLabel => 'Guest ID',
                                guestPasswordLabel => 'Password',
                                username => $username,
                                password => $pwd,
                                provider => 'TDU User',
                                submit => 'Continue',
                                helpButton => 'Help']);

    my $code=$response->code;

    # get response status, headers, body for possible later output
    my $code=$response->code;
    my $desc = HTTP::Status::status_message($code);
    my $headers=$response->headers_as_string;
    my $body =  $response->content;
    $body =  $response->error_as_HTML if ($response->is_error);

    return ($code, $desc, $headers, $body);
}


