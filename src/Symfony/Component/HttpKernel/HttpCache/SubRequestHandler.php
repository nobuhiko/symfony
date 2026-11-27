<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Component\HttpKernel\HttpCache;

use Symfony\Component\HttpFoundation\IpUtils;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * @author Nicolas Grekas <p@tchwork.com>
 *
 * @internal
 */
class SubRequestHandler
{
    /**
     * @return Response
     */
    public static function handle(HttpKernelInterface $kernel, Request $request, $type, $catch)
    {
        $trustedProxies = Request::getTrustedProxies();
        $trustedHeaders = array(
            Request::HEADER_FORWARDED => Request::getTrustedHeaderName(Request::HEADER_FORWARDED),
            Request::HEADER_CLIENT_IP => Request::getTrustedHeaderName(Request::HEADER_CLIENT_IP),
            Request::HEADER_CLIENT_HOST => Request::getTrustedHeaderName(Request::HEADER_CLIENT_HOST),
            Request::HEADER_CLIENT_PROTO => Request::getTrustedHeaderName(Request::HEADER_CLIENT_PROTO),
            Request::HEADER_CLIENT_PORT => Request::getTrustedHeaderName(Request::HEADER_CLIENT_PORT),
        );

        // remove untrusted values
        $remoteAddr = $request->server->get('REMOTE_ADDR');
        // a request built by this method (a nested sub-request) is trusted without trusting 127.0.0.1 globally
        if (!IpUtils::checkIp($remoteAddr, $trustedProxies) && !('127.0.0.1' === $remoteAddr && $request->server->has(Request::SUB_REQUEST_CLIENT_IP_HEADER))) {
            foreach (array_filter($trustedHeaders) as $name) {
                $request->headers->remove($name);
            }
        }

        // compute trusted values, taking any trusted proxies into account
        $trustedIps = array();
        $trustedValues = array();
        foreach (array_reverse($request->getClientIps()) as $ip) {
            $trustedIps[] = $ip;
            $trustedValues[] = sprintf('for="%s"', $ip);
        }
        if ($ip !== $remoteAddr) {
            $trustedIps[] = $remoteAddr;
            $trustedValues[] = sprintf('for="%s"', $remoteAddr);
        }

        // set trusted values, reusing as much as possible the global trusted settings
        if ($name = $trustedHeaders[Request::HEADER_FORWARDED]) {
            $trustedValues[0] .= sprintf(';host="%s";proto=%s', $request->getHttpHost(), $request->getScheme());
            $request->headers->set($name, implode(', ', $trustedValues));
        }
        if ($clientIpHeader = $trustedHeaders[Request::HEADER_CLIENT_IP]) {
            $request->headers->set($clientIpHeader, implode(', ', $trustedIps));
        } elseif (!$trustedHeaders[Request::HEADER_FORWARDED]) {
            $clientIpHeader = 'X_FORWARDED_FOR';
            $request->headers->set('X-Forwarded-For', implode(', ', $trustedIps));
        }

        // fix the client IP address by setting it to 127.0.0.1,
        // which is the core responsibility of this method
        $request->server->set('REMOTE_ADDR', '127.0.0.1');

        // trust 127.0.0.1 for this request and for the ones copied from it, but not globally:
        // other requests coming from 127.0.0.1, like the main one, carry headers set by the client (CVE-2026-133743)
        $request->server->set(Request::SUB_REQUEST_CLIENT_IP_HEADER, (string) $clientIpHeader);

        return $kernel->handle($request, $type, $catch);
    }
}
