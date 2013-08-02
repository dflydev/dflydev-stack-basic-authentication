<?php

require __DIR__.'/../vendor/autoload.php';

use Symfony\Component\HttpFoundation\Request;

$app = new Silex\Application();

$app->register(new Silex\Provider\UrlGeneratorServiceProvider());

$app['debug'] = true;
$app['env'] = 'dev';

$app->get('/', function (Request $request) use ($app) {
    $output = 'Hello!';
    if ($request->attributes->has('stack.authn.token')) {
        $output .= ' Your token is '. $request->attributes->get('stack.authn.token');
    } else {
        $output .= ' <a href="'.$app['url_generator']->generate('login').'">Login</a>';
    }

    return $output;
})->bind('home');

$app->get('/login', function (Request $request) use ($app) {
    return $app->redirect($app['url_generator']->generate('home'));
})->bind('login');

$app = (new Stack\Builder())
    ->push('Dflydev\Stack\BasicAuthentication', [
        'firewall' => [
            ['path' => '/', 'anonymous' => true],
            ['path' => '/login'],
        ],
        'authenticator' => function ($username, $password) {
            if ('admin' === $username && 'default' === $password) {
                return 'admin-user-token';
            }
        },
        'realm' => 'here there be dragons',
    ])
    ->resolve($app);

$request = Request::createFromGlobals();
$response = $app->handle($request)->send();
$app->terminate($request, $response);
