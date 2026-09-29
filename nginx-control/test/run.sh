#!/bin/sh
# Lance toute la suite. Sortie non nulle si un test echoue.
fail=0
for t in "$(dirname "$0")"/*.test.js; do
  echo "═══ $(basename "$t") ═══"
  node "$t" || fail=1
  echo
done
[ $fail -eq 0 ] && echo "TOUS LES TESTS PASSENT" || echo "ECHECS DETECTES"
exit $fail
