<?php

namespace Dflydev\Stack;

use Dflydev\Hawk\Crypto\Crypto;
use Dflydev\Hawk\Header\HeaderFactory;
use Dflydev\Hawk\Server\ServerBuilder;
use Dflydev\Hawk\Server\UnauthorizedException;
use Pimple;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpKernelInterface;

class BasicAuthentication implements HttpKernelInterface
{
    private $app;
    private $container;

    public function __construct(HttpKernelInterface $app, array $options = array())
    {
        $this->app = $app;
        $this->container = $this->setupContainer($options);
    }

    public function handle(Request $request, $type = HttpKernelInterface::MASTER_REQUEST, $catch = true)
    {
        $challenge = function (Response $response) {
            $parts = ['Basic'];
            if (isset($this->container['realm'])) {
                $parts[] = 'realm="'.$this->container['realm'].'"';
            }

            $response->headers->set('WWW-Authenticate', implode(' ', $parts));

            return $response;
        };

        $firewalls = isset($this->container['firewalls'])
            ? $this->container['firewalls']
            : [];

        list ($isResponse, $value, $firewall) = \Stack\Security\authenticate(
            $this->app,
            $challenge,
            $firewalls,
            $request,
            $type,
            $catch
        );

        if ($isResponse) {
            return $value;
        }

        $delegate = $value;

        if (false === $username = $request->headers->get('PHP_AUTH_USER', false)) {
            return call_user_func($delegate);
        }

        $token = $this->container['authenticator']($username, $request->headers->get('PHP_AUTH_PW'));

        if (null === $token) {
            return \Stack\Security\delegate_missing_authentication($firewall, $delegate, $challenge);
        }

        $request->attributes->set('stack.authn.token', $token);

        return call_user_func($delegate);
    }

    private function setupContainer(array $options = array())
    {
        if (!isset($options['authenticator'])) {
            throw new \InvalidArgumentException(
                "The 'authenticator' service must be set"
            );
        }

        $c = new Pimple;

        foreach ($options as $name => $value) {
            if (in_array($name, ['authenticator'])) {
                $c[$name] = $c->protect($value);

                continue;
            }

            $c[$name] = $value;
        }

        return $c;
    }
}
