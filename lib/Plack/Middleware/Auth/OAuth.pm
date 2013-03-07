package Plack::Middleware::Auth::OAuth;
use strict;
use warnings;
our $VERSION = '0.06';

use parent qw(Plack::Middleware);

use Plack::Request;
use Plack::Util::Accessor qw(
    consumer_key
    consumer_secret
    validate_post
    check_timestamp_cb
    check_nonce_cb
    unauthorized_cb
    validate_only
    secret_resolver_cb
    strict
);

use OAuth::Lite::Util qw(parse_auth_header);
use OAuth::Lite::ServerUtil;

sub prepare_app {
    my $self = shift;

    if (!$self->secret_resolver_cb) {
        die 'requires consumer_key'    unless $self->consumer_key;
        die 'requires consumer_secret' unless $self->consumer_secret;
    }

    for my $cb_method (qw/check_nonce_cb check_timestamp_cb unauthorized_cb secret_resolver_cb/) {
        if ($self->$cb_method && ref $self->$cb_method ne 'CODE') {
            die "$cb_method should be a code reference";
        }
    }

}

sub call {
    my ($self, $env) = @_;

    return ($self->validate($env) || $self->validate_only) ? $self->app->($env) : $self->unauthorized($env);
}

sub validate {
    my ($self, $env) = @_;

    my $auth = $env->{HTTP_AUTHORIZATION} or return;

    my ($realm, $params) = parse_auth_header($auth);
    $env->{'psgix.oauth_realm'}  = $realm;
    $env->{'psgix.oauth_params'} = $params;

    my $consumer_secret = $self->consumer_secret;
    if ($self->secret_resolver_cb) {
        $consumer_secret = $self->secret_resolver_cb->($params->{oauth_consumer_key}, $env);
    }
    else {
        return unless $params->{oauth_consumer_key} eq $self->consumer_key;
    }

    return if $self->check_timestamp_cb && !$self->check_timestamp_cb->($params);
    return if $self->check_nonce_cb && !$self->check_nonce_cb->($params);

    my $req = Plack::Request->new($env);
    my $req_params
        = $self->validate_post ? $req->parameters : $req->query_parameters;
    for my $k ($req_params->keys) {
        $params->{$k} = [$req_params->get_all($k)];
    }

    my $util = OAuth::Lite::ServerUtil->new(strict => $self->strict || 0);
    $util->support_signature_method($params->{oauth_signature_method});
    return unless $util->validate_params($params);

    $env->{'psgix.oauth_authorized'} = $util->verify_signature(
        method          => $req->method,
        url             => $req->uri,
        params          => $params,
        consumer_secret => $consumer_secret,
        token_secret    => $params->{oauth_token_secret},
    );
}

sub unauthorized {
    my ($self, $env) = @_;

    if ($self->unauthorized_cb) {
        $self->unauthorized_cb->($env);
    }
    else {
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
          validate_post   => 1,
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

=item unauthorized_cb

A callback function (psgi application) for returning custom response when unauthorized.

=item validate_only

doing only validation. not returning response directly from middleware (unauthorized method not to be called).

discriminating authorization is valid or not by seeing $env->{'psgix.oauth_authorized'} in your app.

=item secret_resolver_cb

A callback function for resolving consumer_secret. This callback takes argument: ($consumer_key, $env).

=item strict

Default: 0

if true, it judge unsupported param as invalid when validating params.
if false, it accepts unsupported parameters.

=back

=head1 AUTHOR

Hideo Kimura E<lt>hide@cpan.orgE<gt>
Masayuki Matsuki E<lt>songmu@cpan.orgE<gt>

=head1 SEE ALSO

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
