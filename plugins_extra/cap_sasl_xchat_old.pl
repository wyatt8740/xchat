# based on cap_sasl.pl by Michael Tharp and Jilles Tjoelker
# ported to X-Chat 2 by Lian Wan Situ
#
# license: GNU General Public License
# Latest version at http://lwsitu.com/xchat/cap_sasl_xchat.pl

### Configuration #######
# How long to wait between authentication messages
my $AUTHENTICATION_TIMEOUT = 15;
### End Configuration ###

use strict;
use warnings;
use Xchat qw(:all);

use MIME::Base64;

register(
	"CAP SASL",
	"1.0107",
	"Implements PLAIN SASL authentication mechanism for use with charybdis ircds, and enables CAP MULTI-PREFIX IDENTIFY-MSG",
	\&cmd_sasl_save,
);


my %timeouts;
my %processing_cap;
hook_print( "Connected", \&event_connected );

hook_server( 'CAP', \&event_cap);
hook_server( 'AUTHENTICATE', \&event_authenticate);
hook_server( '900', sub {
	cap_out( substr( $_[1][5], 1, ) );
	timeout_remove();
	return EAT_XCHAT;
});
hook_server( '903', \&event_saslend);
hook_server( '904', \&event_saslend);
hook_server( '905', \&event_saslend);
hook_server( '906', \&event_saslend);
hook_server( '907', \&event_saslend);

hook_command( 'SASL', \&cmd_sasl, { help_text => cmd_sasl_help_text() } );

my $AUTH_TIMEOUT;
if( $AUTHENTICATION_TIMEOUT ) {
	$AUTH_TIMEOUT = $AUTHENTICATION_TIMEOUT * 1_000;
} else {
	$AUTH_TIMEOUT = 5_000;
}

my %sasl_auth = ();
my %mech = ();

sub send_raw {
	commandf( "QUOTE %s", $_[0] );
}

sub cap {
	send_raw( "CAP " . $_[0] );
}

sub cap_end{
	delete $processing_cap{ get_info "id" };
	cap( "END" );
}

sub connected {
	my $flags = context_info->{flags};
	return  $flags & 1 || $flags & 2;
}

sub get_config_file {
	return get_info( "xchatdirfs" )."/sasl.auth";
}

sub network_name {
	return lc get_info( "network" );
}

# switch to the server tab for the current connection
# return true if successful
sub switch_to_server {
	my $connection_id = shift;

	for my $tab( get_list "channels") {
		if( $tab->{id} == $connection_id && $tab->{type} == 1 ) {
			return set_context( $tab->{context} );
		}
	}

	return;
}

sub cap_out {
	my $output = shift;
	switch_to_server( get_info "id" );

	prnt( $output );
}

sub event_connected {
	cap( "LS" );

	# reset everything for new connection
	timeout_remove();
	delete $processing_cap{ get_info( "id" ) };
	return EAT_NONE;
}

sub event_cap {
	my $tosend = '';
	my $subcmd = uc $_[0][3];
	my $caps = $_[1][4];
	$caps =~ s/^://;

	if ($subcmd eq 'LS') {
		my $id = get_info "id";
		if( $processing_cap{ $id } ) {
			return EAT_XCHAT;
		}
		$processing_cap{ $id } = 1;
		$tosend .= ' multi-prefix' if $caps =~ /\bmulti-prefix\b/xi;

		if( $caps =~ /\bsasl\b/xi ) {
			if( defined($sasl_auth{network_name()}) ) {
				$tosend .= ' sasl';
			} else {
				cap_out( "\cC05SASL is supported but there is no authentication information set for this network(\cC02".network_name()."\cC05)." );
			}
		}

		$tosend .= ' identify-msg' if $caps =~ /\bidentify-msg\b/;
		$tosend =~ s/^ //;
		cap_out( "CLICAP: supported by server: $caps" );

		if ( connected() ) {
			if ($tosend eq '') {
				cap_end();
			} else {
				cap_out( "CLICAP: requesting: $tosend" );
				cap( "REQ :$tosend" );
			}
		}
	} elsif( $subcmd eq 'ACK' ) {
		cap_out( "CLICAP: now enabled: $caps" );

		if( $caps =~ /\bidentify-msg\b/i ) {
			commandf( "RECV %s 290 %s :IDENTIFY-MSG",
				$_[0][0], get_info( "nick" ) );
		}

		if( $caps =~ /\bsasl\b/i ) {
			$sasl_auth{network_name()}{buffer} = '';
			if($mech{$sasl_auth{network_name()}{mech}}) {
				send_raw( "AUTHENTICATE "
					. $sasl_auth{network_name()}{mech}
				);

				timeout_start();
			} else {
				cap_out( 'SASL: attempted to start unknown mechanism "%s"',
					$sasl_auth{network_name()}{mech}
				);
			}
		} elsif( connected() ) {
			cap_end;
		}
	} elsif( $subcmd eq 'NAK' ) {
		cap_out( "CLICAP: refused:$caps" );
		if ( connected() ) {
			cap_end;
		}
	} elsif( $subcmd eq 'LIST' ) {
		cap_out( "CLICAP: currently enabled:$caps" );
	}

	return EAT_XCHAT;
}

sub event_authenticate {
	my $args = $_[1][1] || "";

	my $sasl = $sasl_auth{network_name()};
	return EAT_XCHAT unless $sasl && $mech{$sasl->{mech}};

	$sasl->{buffer} .= $args;
	timeout_reset();
	return EAT_XCHAT if length($args) == 400;

	my $data = $sasl->{buffer} eq '+' ? '' : decode_base64($sasl->{buffer});
	my $out = $mech{$sasl->{mech}}($sasl, $data);
	$out = '' unless defined $out;
	$out = $out eq '' ? '+' : encode_base64($out, '');

	while(length $out >= 400) {
		my $subout = substr($out, 0, 400, '');
		send_raw("AUTHENTICATE $subout");
	}
	if(length $out) {
		send_raw("AUTHENTICATE $out");
	}else{ # Last piece was exactly 400 bytes, we have to send some padding to indicate we're done
		send_raw("AUTHENTICATE +");
	}

	$sasl->{buffer} = '';
	return EAT_XCHAT;
}

sub event_saslend {
	my $data = $_[1][1];
	$data =~ s/^\S+ :?//;
	
	if (connected()) {
		cap_end();
	}

	return EAT_XCHAT;
}

sub timeout_start {
	$timeouts{ context_info->{id} }
		= hook_timer( $AUTH_TIMEOUT, sub { timeout(); return REMOVE; } );
}

sub timeout_remove {
	unhook( $timeouts{ context_info->{id} } ) if $timeouts{ context_info->{id} };
}

sub timeout_reset {
	timeout_remove();
	timeout_start();
}

sub timeout {
	my $id = get_info "id";
	delete $processing_cap{ $id };

	if( connected() ) {
		cap_out( "SASL: authentication timed out" );
		cap_end();
	}
}

my %sasl_actions = (
	load => \&cmd_sasl_load,
	save => \&cmd_sasl_save,
	set => \&cmd_sasl_set,
	delete => \&cmd_sasl_delete,
	show => \&cmd_sasl_show,
	help => \&cmd_sasl_help,
	mechanisms => \&cmd_sasl_mechanisms,
);

sub cmd_sasl {
	my $action = $_[0][1];

	if( $action and my $action_code = $sasl_actions{ $action } ) {
		$action_code->( @_ );
	} else {
		$sasl_actions{ help }->( @_ );
	}

	return EAT_XCHAT;
}

sub cmd_sasl_help_text {
	return <<"HELP_TEXT";
SASL [action] [action paramters]
    actions:
    load        reload SASL information from disk
    save        save the current SASL information to disk
    set         set the SASL information for a particular network
        set <net> <user> <passord or keyfile> <mechanism>
    delete      delete the SASL information for a particular network
        delete <net>

    show        display which networks have SASL information set
    mechanisms  display supported mechanisms

    help        show help message
HELP_TEXT

}

sub cmd_sasl_set {
	my $data = $_[1][2] || "";

	if (my($net, $u, $p, $m) = $data =~ /^(\S+) (\S+) (\S+) (\S+)$/) {
		if($mech{uc $m}) {
			$net = lc $net;
			$sasl_auth{$net}{user} = $u;
			$sasl_auth{$net}{password} = $p;
			$sasl_auth{$net}{mech} = uc $m;
			prnt( "SASL: added $net: [$m] $sasl_auth{$net}{user} *" );
		} else {
			prnt( "SASL: unknown mechanism $m" );
		}
	} elsif( $data =~ /^(\S+)$/) {
		$net = lc $1;
		if (defined($sasl_auth{$net})) {
			delete $sasl_auth{$net};
			prnt( "SASL: deleted $net" );
		} else {
			prnt( "SASL: no entry for $net" );
		}
	} else {
		prnt( "SASL: usage: /sasl set <net> <user> <password or keyfile> <mechanism>" );
	}
}

sub cmd_sasl_delete {
	my $net = $_[0][2];
	prnt "Net: $net";

	delete $sasl_auth{$net};
}

sub cmd_sasl_show {
	foreach my $net (keys %sasl_auth) {
		prnt( "SASL: $net: [$sasl_auth{$net}{mech}] $sasl_auth{$net}{user} *" );
	}
	prnt("SASL: no networks defined") if !%sasl_auth;
}

sub cmd_sasl_save {
	my $file = get_config_file();
	
	if( open my $fh, ">", $file ) {

		foreach my $net (keys %sasl_auth) {
			printf $fh ("%s\t%s\t%s\t%s\n", lc $net, $sasl_auth{$net}{user}, $sasl_auth{$net}{password}, $sasl_auth{$net}{mech});
		}

		prnt( "SASL: auth saved to $file" );
	} else {
		prnt qq{Couldn't open '$file' to save auth data: $!};
	}
}

sub cmd_sasl_load {
	#my ($data, $server, $item) = @_;
	my $file = get_config_file();

	open FILE, "< $file" or return;
	%sasl_auth = ();
	while (<FILE>) {
		chomp;
		my ($net, $u, $p, $m) = split (/\t/, $_, 4);
		$m ||= "PLAIN";
		$net = lc $net;
		if($mech{uc $m}) {
			$sasl_auth{$net}{user} = $u;
			$sasl_auth{$net}{password} = $p;
			$sasl_auth{$net}{mech} = uc $m;
		}else{
			prnt( "SASL: unknown mechanism $m" );
		}
	}
	close FILE;
	prnt( "SASL: auth loaded from $file" );
}

sub cmd_sasl_mechanisms {
	prnt( "SASL: mechanisms supported: " . join(" ", keys %mech) );
}

sub cmd_sasl_help {
	prnt( cmd_sasl_help_text() );
}

$mech{PLAIN} = sub {
	my($sasl, $data) = @_;
	my $u = $sasl->{user};
	my $p = $sasl->{password};

	join("\0", $u, $u, $p);
};

# binary to BigInt
sub bin2bi {
	return Crypt::OpenSSL::Bignum
		->new_from_bin(shift)
		->to_decimal;
}

# BigInt to binary
sub bi2bin {
	return Crypt::OpenSSL::Bignum
		->new_from_decimal((shift)->bstr)
		->to_bin;
}

eval {
	require Crypt::OpenSSL::Bignum;
	require Crypt::DH;
	require Crypt::Blowfish;
	require Math::BigInt;

	$mech{'DH-BLOWFISH'} = sub {
		my($sasl, $data) = @_;
		my $u = $sasl->{user};
		my $pass = $sasl->{password};

		# Generate private key and compute secret key
		my($p, $g, $y) = unpack("(n/a*)3", $data);
		my $dh = Crypt::DH->new(p => bin2bi($p), g => bin2bi($g));
		$dh->generate_keys;

		my $secret = bi2bin($dh->compute_secret(bin2bi($y)));
		my $pubkey = bi2bin($dh->pub_key);

		# Pad the password to the nearest multiple of blocksize and encrypt
		$pass .= "\0";
		$pass .= chr(rand(256)) while length($pass) % 8;

		my $cipher = Crypt::Blowfish->new($secret);
		my $crypted = '';
		while(length $pass) {
			my $clear = substr($pass, 0, 8, '');
			$crypted .= $cipher->encrypt($clear);
		}

		pack("n/a*Z*a*", $pubkey, $u, $crypted);
	};
};

cmd_sasl_load();

# vim: ts=4

