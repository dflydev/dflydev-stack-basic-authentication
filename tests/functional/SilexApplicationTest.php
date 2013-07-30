<?php

namespace functional;

use common\TestCase;
use Pimple;
use Silex\Application;
use Stack\Inline;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Client;
use Symfony\Component\HttpKernel\HttpKernelInterface;

class SilexApplicationTest extends TestCase
{
    /** @test */
    public function shouldNotChallengeForUnprotectedResourceNoHeader()
    {
        $app = $this->basicify($this->createTestApp(), ['firewalls' => [
            ['path' => '/', 'anonymous' => true],
        ]]);

        $client = new Client($app);

        $client->request('GET', '/');
        $this->assertEquals('Root.', $client->getResponse()->getContent());
    }

    /** @test */
    public function shouldChallengeForProtectedResourceNoHeader()
    {
        $app = $this->basicify($this->createTestApp(), ['firewalls' => [
            ['path' => '/', 'anonymous' => true],
        ]]);

        $client = new Client($app);

        $client->request('GET', '/protected/resource');
        $this->assertEquals(401, $client->getResponse()->getStatusCode());
        $this->assertEquals('Basic', $client->getResponse()->headers->get('www-authenticate'));
    }

    /** @test */
    public function shouldChallengeWithExpectedRealm()
    {
        $app = $this->basicify($this->createTestApp(), ['realm' => 'here there be dragons']);

        $client = new Client($app);

        $client->request('GET', '/protected/resource');
        $this->assertEquals(401, $client->getResponse()->getStatusCode());
        $this->assertEquals('Basic realm="here there be dragons"', $client->getResponse()->headers->get('www-authenticate'));
    }

    /** @test */
    public function shouldGetExpectedToken()
    {
        $app = $this->basicify($this->createTestApp());

        $client = new Client($app);

        $client->request('GET', '/protected/token', [], [], [
            'PHP_AUTH_USER' => $this->credentials[0],
            'PHP_AUTH_PW' => $this->credentials[1],
        ]);

        $this->assertEquals($this->credentials[2], $client->getResponse()->getContent());
    }

    /**
     * @test
     * @dataProvider protectedAndUnprotectedResources
     */
    public function shouldAllowAccessToResource($resource, $expectedContent)
    {
        $app = $this->basicify($this->createTestApp());

        $client = new Client($app);

        $client->request('GET', $resource, [], [], [
            'PHP_AUTH_USER' => $this->credentials[0],
            'PHP_AUTH_PW' => $this->credentials[1],
        ]);

        $this->assertEquals($expectedContent, $client->getResponse()->getContent());
    }

    /** @test */
    public function shouldNotClobberExistingToken()
    {
        $authnMiddleware = function(
            HttpKernelInterface $app,
            Request $request,
            $type = HttpKernelInterface::MASTER_REQUEST,
            $catch = true
        ) {
            // We are going to claim that we authenticated...
            $request->attributes->set('stack.authn.token', 'foo');

            // Hawk should actually capture the WWW-Authenticate: Stack response
            // and challenge on its own.
            return $app->handle($request, $type, $catch);
        };

        $app = new Inline($this->basicify($this->createTestApp()), $authnMiddleware);

        $client = new Client($app);

        $client->request('GET', '/protected/token');
        $this->assertEquals('foo', $client->getResponse()->getContent());
    }

    /** @test */
    public function shouldChallengeOnAuthorizationEvenIfOtherMiddlewareAuthenticated()
    {
        $authnMiddleware = function(
            HttpKernelInterface $app,
            Request $request,
            $type = HttpKernelInterface::MASTER_REQUEST,
            $catch = true
        ) {
            // We are going to claim that we authenticated...
            $request->attributes->set('stack.authn.token', 'foo');

            // Hawk should actually capture the WWW-Authenticate: Stack response
            // and challenge on its own.
            return $app->handle($request, $type, $catch);
        };

        $authzMiddleware = function(
            HttpKernelInterface $app,
            Request $request,
            $type = HttpKernelInterface::MASTER_REQUEST,
            $catch = true
        ) {
            // Simulate Authorization failure by returning 401 status
            // code with WWW-Authenticate: Stack.
            $response = (new Response)->setStatusCode(401);
            $response->headers->set('WWW-Authenticate', 'Stack');
            return $response;
        };

        $app = new Inline($this->basicify(new Inline($this->createTestApp(), $authzMiddleware)), $authnMiddleware);

        $client = new Client($app);

        $client->request('GET', '/protected/token');
        $this->assertEquals(401, $client->getResponse()->getStatusCode());
        $this->assertEquals('Basic', $client->getResponse()->headers->get('www-authenticate'));
    }

    protected function createTestApp()
    {
        $app = new Application;
        $app['exception_handler']->disable();

        $app->get('/', function () {
            return 'Root.';
        });

        $app->get('/protected/resource', function () {
            return 'Protected Resource.';
        });

        $app->get('/protected/token', function (Request $request) {
            return $request->attributes->get('stack.authn.token');
        });

        // Simple Silex middleware to always let certain requests go through
        // and to always throw 401 responses in all other cases *unless*
        // stack.authn.token has been set correctly.
        $app->before(function (Request $request) {
            if (in_array($request->getRequestUri(), array('/'))) {
                return;
            }

            if (!$request->attributes->has('stack.authn.token')) {
                $response = (new Response)->setStatusCode(401);
                $response->headers->set('WWW-Authenticate', 'Stack');

                return $response;
            }
        });

        return $app;
    }

    public function protectedAndUnprotectedResources()
    {
        return [
            ['/', 'Root.'],
            ['/protected/resource', 'Protected Resource.'],
        ];
    }
}
