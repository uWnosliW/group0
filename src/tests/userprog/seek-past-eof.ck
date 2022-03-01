# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(seek-past-eof) begin
(seek-past-eof) created testing.txt
(seek-past-eof) open "testing.txt"
(seek-past-eof) end
seek-past-eof: exit(0)
EOF
pass;