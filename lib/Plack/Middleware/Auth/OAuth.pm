package Plack::Middleware::Auth::OAuth;
use strict;
use warnings;
our $VERSION = '0.04';

use parent qw(Plack::Middleware);

use Plack::Request;
use Plack::Util::Accessor qw(
    consumer_key
    consumer_secret
    validate_post
    check_timestamp_cb
    check_nonce_cb
);

use OAuth::Lite::Util qw(parse_auth_header);
use OAuth::Lite::ServerUtil;

sub prepare_app {
    my $self = shift;

    die 'requires consumer_key'    unless $self->consumer_key;
    die 'requires consumer_secret' unless $self->consumer_secret;

    if ($self->check_nonce_cb && ref $self->check_nonce_cb ne 'CODE') {
        die 'check_nonce_cb should be a code reference';
    }
    if ($self->check_timestamp_cb && ref $self->check_timestamp_cb ne 'CODE')
    {
        die 'check_timestamp_cb should be a code reference';
    }
}

sub call {
    my ($self, $env) = @_;

    return $self->validate($env) ? $self->app->($env) : $self->unauthorized;
}

sub validate {
    my ($self, $env) = @_;

    my $auth = $env->{HTTP_AUTHORIZATION} or return;

    my ($realm, $params) = parse_auth_header($auth);
    $env->{'psgix.oauth_realm'}  = $realm;
    $env->{'psgix.oauth_params'} = $params;

    return unless $params->{oauth_consumer_key} eq $self->consumer_key;

    return if $self->check_timestamp_cb && !$self->check_timestamp_cb->($params);
    return if $self->check_nonce_cb && !$self->check_nonce_cb->($params);

    my $req = Plack::Request->new($env);
    my $req_params
        = $self->validate_post ? $req->parameters : $req->query_parameters;
    for my $k ($req_params->keys) {
        $params->{$k} = [$req_params->get_all($k)];
    }

    my $util = OAuth::Lite::ServerUtil->new(strict => 0);
    $util->support_signature_method($params->{oauth_signature_method});
    return unless $util->validate_params($params);

    return $util->verify_signature(
        method          => $req->method,
        url             => $req->uri,
        params          => $params,
        consumer_secret => $self->consumer_secret,
        token_secret    => $params->{oauth_token_secret},
    );
}

sub unauthorized {
    my $self = shift;

    my $body = 'Authorization required';
    return [
        401,
        [
            'Content-Type'    => 'text/plain',
            'Content-Lentgth' => length $body,
        ],
        [$body],
    ];
}
1;
__END__

=head1 NAME

Plack::Middleware::Auth::OAuth - OAuth signature validation middleware

=head1 SYNOPSIS

  use Plack::Builder;

  my $app = sub { ...};

  builder {
      enable "Plack::Middleware::Auth::OAuth",
          consumer_key => 'YOUR_CONSUMER_KEY',
          consumer_secret => 'YOUR_CONSUMER_SECRET',
          ;
      $app; 
  };

=head1 DESCRIPTION

Plack::Middleware::Auth::OAuth is OAuth signature validation handler for Plack.

=head1 CONFIGURATION

=over 4

=item consumer_key

Your application's consumer key.

=item consumer_secret

Your application's consumer secret.

=item validate_post

Includes body parameters in validation.  For MBGA-Town, you should use this 
option.

=item check_nonce_cb 

A callback function to validate oauth_nonce.

=item check_timestamp_cb 

A callback function to validate oauth_timestamp.

=back

=head1 AUTHOR

Hideo Kimura E<lt>hide@cpan.orgE<gt>
Masayuki Matsuki E<lt>songmu@cpan.orgE<gt>

=head1 SEE ALSO

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
