<?php

namespace common;

use Dflydev\Hawk\Credentials\Credentials;
use Dflydev\Stack\BasicAuthentication;
use Symfony\Component\HttpKernel\HttpKernelInterface;

abstract class TestCase extends \PHPUnit_Framework_TestCase
{
    protected $credentials;

    public function setUp()
    {
        $this->credentials = ['username1234', 'password1234', 'token1234'];
    }

    protected function basicify(HttpKernelInterface $app, array $config = [])
    {
        $config = array_merge([
            'authenticator' => function ($username = null, $password = null) {
                if ($this->credentials[0] === $username && $this->credentials[1] === $password) {
                    return $this->credentials[2];
                }
            }
        ], $config);

        return new BasicAuthentication($app, $config);
    }
}
