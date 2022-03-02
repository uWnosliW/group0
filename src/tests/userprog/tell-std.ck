# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(tell-std) begin
(tell-std) created testing.txt
(tell-std) open "testing.txt"
(tell-std) end
tell-std: exit(0)
EOF
pass;