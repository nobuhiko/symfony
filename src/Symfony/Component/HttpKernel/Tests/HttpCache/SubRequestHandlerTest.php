<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Component\HttpKernel\Tests\HttpCache;

use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpCache\SubRequestHandler;
use Symfony\Component\HttpKernel\HttpKernelInterface;

class SubRequestHandlerTest extends TestCase
{
    private static $globalState;

    protected function setUp()
    {
        self::$globalState = $this->getGlobalState();
    }

    protected function tearDown()
    {
        foreach (self::$globalState[1] as $key => $name) {
            Request::setTrustedHeaderName($key, $name);
        }
        Request::setTrustedProxies(self::$globalState[0]);
    }

    public function testTrustedHeadersAreKept()
    {
        Request::setTrustedProxies(array('10.0.0.1'));
        $globalState = $this->getGlobalState();

        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '10.0.0.1');
        $request->headers->set('X-Forwarded-For', '10.0.0.2');
        $request->headers->set('X-Forwarded-Host', 'Good');
        $request->headers->set('X-Forwarded-Port', '1234');
        $request->headers->set('X-Forwarded-Proto', 'https');

        $that = $this;
        $kernel = new TestSubRequestHandlerKernel(function ($request, $type, $catch) use ($that) {
            $that->assertSame('127.0.0.1', $request->server->get('REMOTE_ADDR'));
            $that->assertSame('10.0.0.2', $request->getClientIp());
            $that->assertSame('Good', $request->headers->get('X-Forwarded-Host'));
            $that->assertSame('1234', $request->headers->get('X-Forwarded-Port'));
            $that->assertSame('https', $request->headers->get('X-Forwarded-Proto'));
        });

        SubRequestHandler::handle($kernel, $request, HttpKernelInterface::MASTER_REQUEST, true);

        $this->assertSame($globalState, $this->getGlobalState());
    }

    public function testUntrustedHeadersAreRemoved()
    {
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '10.0.0.1');
        $request->headers->set('X-Forwarded-For', '10.0.0.2');
        $request->headers->set('X-Forwarded-Host', 'Evil');
        $request->headers->set('X-Forwarded-Port', '1234');
        $request->headers->set('X-Forwarded-Proto', 'http');
        $request->headers->set('Forwarded', 'Evil2');

        $that = $this;
        $kernel = new TestSubRequestHandlerKernel(function ($request, $type, $catch) use ($that) {
            $that->assertSame('127.0.0.1', $request->server->get('REMOTE_ADDR'));
            $that->assertSame('10.0.0.1', $request->getClientIp());
            $that->assertFalse($request->headers->has('X-Forwarded-Host'));
            $that->assertFalse($request->headers->has('X-Forwarded-Port'));
            $that->assertFalse($request->headers->has('X-Forwarded-Proto'));
            $that->assertSame('for="10.0.0.1";host="localhost";proto=http', $request->headers->get('Forwarded'));
        });

        SubRequestHandler::handle($kernel, $request, HttpKernelInterface::MASTER_REQUEST, true);

        $this->assertSame(self::$globalState, $this->getGlobalState());
    }

    public function testTrustedForwardedHeader()
    {
        Request::setTrustedProxies(array('10.0.0.1'));
        $globalState = $this->getGlobalState();

        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '10.0.0.1');
        $request->headers->set('Forwarded', 'for="10.0.0.2";host="foo.bar:1234";proto=https');

        $that = $this;
        $kernel = new TestSubRequestHandlerKernel(function ($request, $type, $catch) use ($that) {
            $that->assertSame('127.0.0.1', $request->server->get('REMOTE_ADDR'));
            $that->assertSame('10.0.0.2', $request->getClientIp());
        });

        SubRequestHandler::handle($kernel, $request, HttpKernelInterface::MASTER_REQUEST, true);

        $this->assertSame($globalState, $this->getGlobalState());
    }

    public function testTrustedXForwardedForHeader()
    {
        Request::setTrustedProxies(array('10.0.0.1'));
        $globalState = $this->getGlobalState();

        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '10.0.0.1');
        $request->headers->set('X-Forwarded-For', '10.0.0.2');
        $request->headers->set('X-Forwarded-Host', 'foo.bar');
        $request->headers->set('X-Forwarded-Proto', 'https');

        $that = $this;
        $kernel = new TestSubRequestHandlerKernel(function ($request, $type, $catch) use ($that) {
            $that->assertSame('127.0.0.1', $request->server->get('REMOTE_ADDR'));
            $that->assertSame('10.0.0.2', $request->getClientIp());
            $that->assertSame('foo.bar', $request->getHttpHost());
            $that->assertSame('https', $request->getScheme());
        });

        SubRequestHandler::handle($kernel, $request, HttpKernelInterface::MASTER_REQUEST, true);

        $this->assertSame($globalState, $this->getGlobalState());
    }

    public function testOtherRequestsFromLocalhostAreNotTrusted()
    {
        $mainRequest = Request::create('https://example.com/');
        $mainRequest->server->set('REMOTE_ADDR', '127.0.0.1');
        $mainRequest->headers->set('X-Forwarded-For', '10.0.0.2');
        $mainRequest->headers->set('X-Forwarded-Host', 'evil.example');
        $mainRequest->headers->set('X-Forwarded-Proto', 'http');

        $that = $this;
        $kernel = new TestSubRequestHandlerKernel(function ($request, $type, $catch) use ($that, $mainRequest) {
            $that->assertSame('example.com', $request->getHost());
            $that->assertSame('127.0.0.1', $mainRequest->getClientIp());
            $that->assertSame('example.com', $mainRequest->getHost());
            $that->assertTrue($mainRequest->isSecure());
        });

        $subRequest = Request::create('/_fragment', 'GET', array(), array(), array(), $mainRequest->server->all());
        SubRequestHandler::handle($kernel, $subRequest, HttpKernelInterface::SUB_REQUEST, false);

        $this->assertSame(self::$globalState, $this->getGlobalState());
    }

    public function testNestedSubRequestsKeepTheClientIp()
    {
        Request::setTrustedHeaderName(Request::HEADER_CLIENT_IP, '');
        Request::setTrustedHeaderName(Request::HEADER_FORWARDED, '');

        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '10.0.0.1');

        $that = $this;
        $kernel = new TestSubRequestHandlerKernel(function ($request, $type, $catch) use ($that) {
            $that->assertSame('10.0.0.1', $request->getClientIp());

            $fragmentKernel = new TestSubRequestHandlerKernel(function ($fragment, $type, $catch) use ($that) {
                $that->assertSame('127.0.0.1', $fragment->server->get('REMOTE_ADDR'));
                $that->assertSame('10.0.0.1', $fragment->getClientIp());
            });

            SubRequestHandler::handle($fragmentKernel, $request->duplicate(), HttpKernelInterface::SUB_REQUEST, false);
        });

        SubRequestHandler::handle($kernel, $request, HttpKernelInterface::MASTER_REQUEST, true);

        $this->assertSame('', Request::getTrustedHeaderName(Request::HEADER_CLIENT_IP));
        $this->assertSame(array(), Request::getTrustedProxies());
    }

    private function getGlobalState()
    {
        return array(
            Request::getTrustedProxies(),
            array(
                Request::HEADER_FORWARDED => Request::getTrustedHeaderName(Request::HEADER_FORWARDED),
                Request::HEADER_CLIENT_IP => Request::getTrustedHeaderName(Request::HEADER_CLIENT_IP),
                Request::HEADER_CLIENT_HOST => Request::getTrustedHeaderName(Request::HEADER_CLIENT_HOST),
                Request::HEADER_CLIENT_PROTO => Request::getTrustedHeaderName(Request::HEADER_CLIENT_PROTO),
                Request::HEADER_CLIENT_PORT => Request::getTrustedHeaderName(Request::HEADER_CLIENT_PORT),
            ),
        );
    }
}

class TestSubRequestHandlerKernel implements HttpKernelInterface
{
    private $assertCallback;

    public function __construct(\Closure $assertCallback)
    {
        $this->assertCallback = $assertCallback;
    }

    public function handle(Request $request, $type = self::MASTER_REQUEST, $catch = true)
    {
        $assertCallback = $this->assertCallback;
        $assertCallback($request, $type, $catch);

        return new Response();
    }
}
