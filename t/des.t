BEGIN { push @INC, qw(. .. ../lib ../../lib ../../../lib) }

use Des;

print "1..5\n";

$rand = Des::random_key();
print length($rand) == 8 ? "ok 1\n" : "not ok 1\n";

$key = string_to_key("Hello world");
print $key eq "\332\127\241\172\266\153\241\304" ? "ok 2\n" : "not ok 2\n";

$schedule = set_key($key);

$clear = "The quick brown fox";
$ciph = pcbc_encrypt($clear, undef, $schedule, "\0"x8);

print $ciph eq "\5\27\132\51\102\374\122\163\115\322\230\311\246\372\101\214\110\212\142\52\67\125\265\35" ? "ok 3\n" : "not ok 3\n";

pcbc_decrypt($ciph, $newclear, $schedule, "\0"x8);
print $newclear eq $clear."\0\0\0\0\0" ? "ok 4\n" : "not ok 4\n";

$cksum = cbc_cksum($clear, $schedule, "\0"x8);
print $cksum eq "\323\347\17\121\47\0\354\207" ? "ok 5\n" : "not ok 5\n";
