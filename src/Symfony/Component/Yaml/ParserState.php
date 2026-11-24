<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Component\Yaml;

use Symfony\Component\Yaml\Exception\ParseException;

/**
 * Bounds what a single YAML document can make the parser do.
 *
 * Backport to 2.7 of the limits added upstream for CVE-2026-45133, CVE-2026-109413,
 * CVE-2026-45304 and CVE-2026-123792. The 2.7 parser creates one Parser instance
 * per nested block and Inline is static, so the state is static as well.
 *
 * @internal
 */
final class ParserState
{
    const MAX_NESTING_LEVEL = 128;
    const MAX_ALIASES_FOR_COLLECTIONS = 128;
    // nested blocks are copied at each nesting level by the 2.7 parser: bytes + 128 per line, summed over the open levels.
    // PHP 5 uses about 5 bytes of memory per unit, so 16M stays under the default memory_limit of 128M
    const MAX_NESTED_BLOCK_COST = 16777216;

    public static $active = 0;
    public static $nestingLevel = 0;
    public static $collectionAliasCount = 0;
    public static $nodeCount = 0;
    public static $aliasedNodeCount = 0;
    public static $maxAliasedNodeCount = PHP_INT_MAX;
    public static $anchorNodeCounts = array();
    public static $nestedBlockCost = 0;

    public static function start($documentLength)
    {
        if (0 === self::$active++) {
            self::reset();
            self::$maxAliasedNodeCount = self::MAX_ALIASES_FOR_COLLECTIONS * max(1, $documentLength);
        }
    }

    public static function end()
    {
        if (self::$active > 0 && 0 === --self::$active) {
            self::reset();
        }
    }

    private static function reset()
    {
        self::$nestingLevel = 0;
        self::$collectionAliasCount = 0;
        self::$nodeCount = 0;
        self::$aliasedNodeCount = 0;
        self::$maxAliasedNodeCount = PHP_INT_MAX;
        self::$anchorNodeCounts = array();
        self::$nestedBlockCost = 0;
    }

    public static function enterNestingLevel($line = -1, $snippet = null)
    {
        if (++self::$nestingLevel > self::MAX_NESTING_LEVEL) {
            --self::$nestingLevel;

            throw new ParseException(sprintf('Maximum nesting depth of %d exceeded.', self::MAX_NESTING_LEVEL), $line, $snippet);
        }
    }

    public static function leaveNestingLevel()
    {
        if (self::$nestingLevel > 0) {
            --self::$nestingLevel;
        }
    }

    public static function enterNestedBlock($yaml, $line = -1, $snippet = null)
    {
        $cost = strlen($yaml) + 128 * (1 + substr_count($yaml, "\n"));

        if ((self::$nestedBlockCost += $cost) > self::MAX_NESTED_BLOCK_COST) {
            throw new ParseException('Maximum size of nested blocks exceeded.', $line, $snippet);
        }

        return $cost;
    }

    public static function leaveNestedBlock($cost)
    {
        self::$nestedBlockCost = max(0, self::$nestedBlockCost - $cost);
    }

    /**
     * @param string $name
     * @param mixed  $refValue
     */
    public static function countAlias($name, $refValue, $line = -1, $snippet = null)
    {
        if (0 === self::$active || (!is_array($refValue) && !$refValue instanceof \stdClass)) {
            return;
        }

        if (++self::$collectionAliasCount > self::MAX_ALIASES_FOR_COLLECTIONS) {
            throw new ParseException(sprintf('Maximum number of collection aliases (%d) exceeded.', self::MAX_ALIASES_FOR_COLLECTIONS), $line, $snippet);
        }

        // an alias shares the nodes of its anchor, but the code that walks the parsed value visits them once per alias
        $nodeCount = isset(self::$anchorNodeCounts[$name]) ? self::$anchorNodeCounts[$name] : 0;
        self::$nodeCount += $nodeCount;

        if ((self::$aliasedNodeCount += $nodeCount) > self::$maxAliasedNodeCount) {
            throw new ParseException(sprintf('Maximum number of nodes expanded by collection aliases (%d) exceeded.', self::$maxAliasedNodeCount), $line, $snippet);
        }
    }
}
