<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Component\Validator\Constraints;

use Symfony\Component\Validator\Context\ExecutionContextInterface;
use Symfony\Component\Validator\Constraint;
use Symfony\Component\Validator\ConstraintValidator;
use Symfony\Component\Validator\Exception\UnexpectedTypeException;

/**
 * Validates whether a value is a valid IP address.
 *
 * @author Bernhard Schussek <bschussek@gmail.com>
 * @author Joseph Bielawski <stloyd@gmail.com>
 */
class IpValidator extends ConstraintValidator
{
    /**
     * IPv4 subnets that cannot be reached over the public internet (IANA IPv4 Special-Purpose Address Registry, RFC 6890).
     * filter_var() covers only some of them, and none of the IPv6 spellings of an IPv4 address.
     */
    private static $nonPublicV4Subnets = array(
        '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12',
        '192.0.2.0/24', '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '240.0.0.0/4',
    );

    /**
     * IPv6 subnets that cannot be reached over the public internet, either because they
     * are special-purpose or because they carry a non-public IPv4 address.
     */
    private static $nonPublicV6Subnets = array(
        '::1/128', 'fc00::/7', 'fe80::/10', '::ffff:0:0/96', '::/96', '2002::/16', '2001::/32',
        '2001:db8::/32', '2001:0002::/48', '64:ff9b::/96', '64:ff9b:1::/48',
    );

    /**
     * Tells whether an address belongs to one of the non-public subnets, whatever its textual spelling.
     */
    private static function isNonPublicIp($ip)
    {
        $bin = @inet_pton($ip);
        if (false === $bin) {
            return false;
        }

        foreach (4 === strlen($bin) ? self::$nonPublicV4Subnets : self::$nonPublicV6Subnets as $subnet) {
            list($net, $bits) = explode('/', $subnet);
            $netBin = inet_pton($net);
            $bits = (int) $bits;
            $bytes = (int) ($bits / 8);
            if ($bytes && 0 !== strncmp($bin, $netBin, $bytes)) {
                continue;
            }
            $rest = $bits % 8;
            if ($rest) {
                $mask = (0xff << (8 - $rest)) & 0xff;
                if ((ord($bin[$bytes]) & $mask) !== (ord($netBin[$bytes]) & $mask)) {
                    continue;
                }
            }

            return true;
        }

        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function validate($value, Constraint $constraint)
    {
        if (!$constraint instanceof Ip) {
            throw new UnexpectedTypeException($constraint, __NAMESPACE__.'\Ip');
        }

        if (null === $value || '' === $value) {
            return;
        }

        if (!is_scalar($value) && !(is_object($value) && method_exists($value, '__toString'))) {
            throw new UnexpectedTypeException($value, 'string');
        }

        $value = (string) $value;

        switch ($constraint->version) {
            case Ip::V4:
               $flag = FILTER_FLAG_IPV4;
               break;

            case Ip::V6:
               $flag = FILTER_FLAG_IPV6;
               break;

            case Ip::V4_NO_PRIV:
               $flag = FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE;
               break;

            case Ip::V6_NO_PRIV:
               $flag = FILTER_FLAG_IPV6 | FILTER_FLAG_NO_PRIV_RANGE;
               break;

            case Ip::ALL_NO_PRIV:
               $flag = FILTER_FLAG_NO_PRIV_RANGE;
               break;

            case Ip::V4_NO_RES:
               $flag = FILTER_FLAG_IPV4 | FILTER_FLAG_NO_RES_RANGE;
               break;

            case Ip::V6_NO_RES:
               $flag = FILTER_FLAG_IPV6 | FILTER_FLAG_NO_RES_RANGE;
               break;

            case Ip::ALL_NO_RES:
               $flag = FILTER_FLAG_NO_RES_RANGE;
               break;

            case Ip::V4_ONLY_PUBLIC:
               $flag = FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE;
               break;

            case Ip::V6_ONLY_PUBLIC:
               $flag = FILTER_FLAG_IPV6 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE;
               break;

            case Ip::ALL_ONLY_PUBLIC:
               $flag = FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE;
               break;

            default:
                $flag = null;
                break;
        }

        $isValid = (bool) filter_var($value, FILTER_VALIDATE_IP, $flag);

        if ($isValid && $flag & (FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            $isValid = !self::isNonPublicIp($value);
        }

        if (!$isValid) {
            if ($this->context instanceof ExecutionContextInterface) {
                $this->context->buildViolation($constraint->message)
                    ->setParameter('{{ value }}', $this->formatValue($value))
                    ->addViolation();
            } else {
                $this->buildViolation($constraint->message)
                    ->setParameter('{{ value }}', $this->formatValue($value))
                    ->addViolation();
            }
        }
    }
}
