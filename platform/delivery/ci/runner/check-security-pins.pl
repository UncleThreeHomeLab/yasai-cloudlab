use strict;
use warnings;
use JSON::PP;
use Digest::SHA qw(sha256_hex);
use MIME::Base64 qw(decode_base64 encode_base64);

my $root = '/source/runner-integrity';
my $src = '/source/runner/src';
my $json = JSON::PP->new->utf8;

sub read_file {
    my ($path) = @_;
    open my $fh, '<:raw', $path or die "Cannot read integrity input: $path\n";
    local $/;
    return <$fh>;
}

# JSON::PP otherwise silently accepts duplicate object keys.
sub checked_json {
    my ($text) = @_;
    my $pos = 0;
    my $ws = sub { $pos++ while $pos < length($text) && substr($text, $pos, 1) =~ /[\x20\x09\x0a\x0d]/ };
    my $string = sub {
        substr($text, $pos, 1) eq '"' or die "Expected JSON string\n";
        my ($value, $length) = $json->decode_prefix(substr($text, $pos));
        defined($value) && !ref($value) or die "Invalid JSON string\n";
        $pos += $length;
        return $value;
    };
    my $value;
    $value = sub {
        $ws->();
        my $char = substr($text, $pos, 1);
        if ($char eq '{') {
            $pos++; $ws->(); my %keys;
            if (substr($text, $pos, 1) eq '}') { $pos++; return; }
            while (1) {
                $ws->(); my $key = $string->();
                !$keys{$key}++ or die "Duplicate JSON key\n";
                $ws->(); substr($text, $pos++, 1) eq ':' or die "Invalid JSON object\n";
                $value->(); $ws->();
                my $next = substr($text, $pos++, 1);
                last if $next eq '}';
                $next eq ',' or die "Invalid JSON object separator\n";
            }
        } elsif ($char eq '[') {
            $pos++; $ws->();
            if (substr($text, $pos, 1) eq ']') { $pos++; return; }
            while (1) {
                $value->(); $ws->(); my $next = substr($text, $pos++, 1);
                last if $next eq ']';
                $next eq ',' or die "Invalid JSON array separator\n";
            }
        } else {
            my (undef, $length) = $json->decode_prefix(substr($text, $pos));
            $length > 0 or die "Invalid JSON value\n";
            $pos += $length;
        }
    };
    $value->(); $ws->(); $pos == length($text) or die "Trailing JSON data\n";
    return $json->decode($text);
}

my $lock = checked_json(read_file("$root/source.lock.json"));
my %owners = (
    'System.Security.Cryptography.Pkcs' => 'Sdk',
    'System.Formats.Asn1' => 'Sdk',
    'Microsoft.AspNetCore.WebUtilities' => 'Runner.Worker',
);
ref($lock->{security_packages}) eq 'HASH' or die "Missing security packages\n";
join("\0", sort keys %{$lock->{security_packages}}) eq join("\0", sort keys %owners)
    or die "Unexpected security package keys\n";
my %required_hashes = (
    overlays => [qw(runner.patch TrustedWorkflow.cs TrustedTemplate.cs health.py tests/Fixtures.cs tests/TrustedWorkflowL0.cs)],
    nuget => [qw(Runner.Common Runner.Listener Runner.PluginHost Runner.Plugins Runner.Sdk Runner.Worker Sdk Test)],
);
for my $section (qw(overlays nuget)) {
    ref($lock->{$section}) eq 'HASH' or die "Missing integrity hashes\n";
    join("\0", sort keys %{$lock->{$section}}) eq join("\0", sort @{$required_hashes{$section}})
        or die "Unexpected integrity hash keys\n";
    for my $name (keys %{$lock->{$section}}) {
        $name =~ /\A[A-Za-z0-9_.\/-]+\z/ && $name !~ /(?:\A|\/)\.\.(?:\/|\z)/ or die "Invalid integrity path\n";
        my $path = $section eq 'overlays' ? "$root/$name" : "$root/nuget/$name/packages.lock.json";
        my $expected = $lock->{$section}{$name};
        defined($expected) && $expected =~ /\A[a-f0-9]{64}\z/ && sha256_hex(read_file($path)) eq $expected
            or die "Integrity hash mismatch: $name\n";
    }
}
for my $owner (sort keys %{ { map { $owners{$_} => 1 } keys %owners } }) {
    open my $msbuild, '-|', 'dotnet', 'msbuild', "$src/$owner/$owner.csproj", '-getItem:PackageReference', '-p:Version=2.338.0'
        or die "Cannot evaluate project\n";
    local $/; my $out = <$msbuild>; close $msbuild or die "Project evaluation failed\n";
    my $items = checked_json($out)->{Items}{PackageReference};
    ref($items) eq 'ARRAY' or die "Missing project references\n";
    for my $name (grep { $owners{$_} eq $owner } keys %owners) {
        my $version = $lock->{security_packages}{$name};
        defined($version) && !ref($version) && $version =~ /\A\d+\.\d+\.\d+\z/ or die "Invalid pinned version\n";
        my @items = grep { lc($_->{Identity} // '') eq lc($name) } @$items;
        @items == 1 && $items[0]{Identity} eq $name && ($items[0]{Version} // '') eq $version
            or die "Project package mismatch: $name\n";
    }
}
for my $project (qw(Sdk Runner.Worker Test)) {
    my $packages = checked_json(read_file("$root/nuget/$project/packages.lock.json"))->{dependencies};
    ref($packages) eq 'HASH' && ref($packages->{'net8.0'}) eq 'HASH' or die "Missing base target\n";
    for my $name (keys %owners) {
        next if $project eq 'Sdk' && $owners{$name} ne 'Sdk';
        my $base = $packages->{'net8.0'}{$name};
        ref($base) eq 'HASH' or die "Missing base package: $project $name\n";
        my $version = $lock->{security_packages}{$name};
        my $hash = $base->{contentHash} // '';
        ($base->{resolved} // '') eq $version && $hash =~ /\A[A-Za-z0-9+\/]{86}==\z/ && encode_base64(decode_base64($hash), '') eq $hash
            or die "Invalid base package: $project $name\n";
        ($base->{type} // '') eq 'Direct' or die "Missing direct package: $name\n" if $owners{$name} eq $project;
        for my $target (grep { /^net8\.0\// } keys %$packages) {
            ref($packages->{$target}) eq 'HASH' or die "Invalid RID target\n";
            next unless exists $packages->{$target}{$name};
            my $entry = $packages->{$target}{$name};
            ref($entry) eq 'HASH' && ($entry->{resolved} // '') eq $version && ($entry->{contentHash} // '') eq $hash
                or die "RID package mismatch: $project $name\n";
        }
    }
}
print "Runner security pin integrity verified\n";
