#!perl -w
# lame try to reconstruct sw64 opcodes ripped from libopcodes-2.31.1-system.so
# 28 may 2022 (c) redplait
use strict;
use warnings;
use Getopt::Std;
use Data::Dumper;

use vars qw/$opt_d $opt_v/;

sub HELP_MESSAGE()
{
    print STDERR <<EOF;
Usage is $0 [options] opcodes
Options:
  -d -- make tables for standalone disasm
  -v -- verbose mode
EOF
    exit (8);
}

# c is lowest 16 bits in ops, zero is 7
sub is_zc
{
  my $op = shift;
  return 7 == ($op & 0xff);
}

sub clear_zc
{
  my $op = shift;
  return ($op & ~0x1f);
}

sub insert_zc
{
  my $insn = shift;
  return $insn | 31;
}

# b is middle 16 bits, zero is B
sub is_zb
{
  my $op = shift;
  return 8 == (($op >> 8) & 0xff);
}

sub is_fzb
{
  my $op = shift;
  return 0xc == (($op >> 8) & 0xff );
}

sub clear_zb
{
  my $op = shift;
  return ($op & ~0x1f00 );
}

sub insert_zb
{
  my $insn = shift;
  return $insn | (31 << 16);
}

# za is 16bit from 8, zero is 9
sub get_za
{
  my $op = shift;
  return ($op >> 16) & 0xff;
}

sub is_za
{
  my $op = shift;
  return 9 == (($op >> 16) & 0xff );
}

sub clear_za
{
  my $op = shift;
  return ($op & ~0x1f0000 );
}

sub insert_za
{
  my $insn = shift;
  return $insn | (31 << 21);
}

sub dump_same
{
  my($ah, $names, $is_hex) = @_;
  my $total = 0;
  my $same = 0;
  foreach my $name ( @$names )
  {
    $total++;
    next if ( !exists $ah->{$name} );
    $same++;
    if ( $is_hex )
    {
      printf("%s, 0x%X\n", $name, $ah->{$name});
    } else {
      printf("%s, %s\n", $name, $ah->{$name});
    }
  }
  return ($total, $same);
}

sub dump_header
{
print<<EOF;
// this file was generated with script ops.pl
// do not edit it
EOF
}

sub dump_enum
{
  my $names = shift;
  printf("enum sw64_insn_type_t {\n");
  my $id = 0;
  foreach my $n ( @$names )
  {
     # replace / with _
     my $ename = $n->[0];
     $ename =~ s/\//_/g;
#    if ( !$id )
#    {
#      printf(" LOONG_%s = CUSTOM_INSN_ITYPE,\n", $n);
#      $id++;
#    } else {
      printf(" sw64_%s,\n", $ename);
#    }
  }
  printf("};\n\n");
}

sub dump_simple_names
{
  my $names = shift;
  my $id = 0;
  printf("const char *Instructions[] = {\n");
  foreach my $n ( @$names )
  {
    # replace / with _
    my $ename = $n->[0];
    $ename =~ s/\//_/g;
    printf(" \"%s\", /* sw64_%s %X */\n", $n->[0], $ename, $n->[1]);
  }
  printf("};\n\n");  
}

sub dump_opnames
{
  if ( defined $opt_d )
  {
    dump_simple_names(@_);
    return;
  }
  my $names = shift;
  my $id = 0;
  printf("const instruc_t Instructions[] = {\n");
  foreach my $n ( @$names )
  {
    # replace / with _
    my $ename = $n->[0];
    $ename =~ s/\//_/g;
    # lets make flags for instruc_t
    my $s = '';
    if ( $n->[1] == 0x1701 || $n->[1] == 0x1704 || $n->[1] == 0x1700 )
    {
      $s = "CF_USE1 | CF_JUMP";
    } 
    elsif ( $ename eq 'bpt' || $ename eq 'bugchk' || $ename eq 'ret' )
    {
      $s = "CF_STOP";
    }
    elsif ( $ename eq 'jmp' )
    {
      $s = "CF_USE1 | CF_JUMP | CF_STOP";
    }
    elsif ( $ename eq 'call' )
    {
      $s .= "CF_CALL";
    } else {
     # rc - destination
     my $cr = $n->[1] & 0x20000;
     if ( $cr )
     {
       $s .= "| " if ( $s ne '' );
       $s .= "CF_CHG1";
     }
     # rb - 2nd reg
     my $br = $n->[1] & 0xf00;
     if ( $br )
     {
       $s .= "| " if ( $s ne '' );
       $s .= "CF_USE2";
     }
     # ra - 3rd reg
     my $ar = $n->[1] & 0xff;
     if ( $ar == 1 || $ar == 4 )
     {
       $s .= "| " if ( $s ne '' );
       $s .= "CF_USE3";
     }
    }
    $s = '0' if ( $s eq '' );
    printf(" { \"%s\", %s }, /* sw64_%s %X */\n", $n->[0], $s, $ename, $n->[1]);
  }
  printf("};\n\n");  
}

sub dump_decode
{
print<<EOF;
int decode_sw64(uint32 value, sw64_insn_type_t &op, uint32 &mask, uint32 &ops)
{
EOF
  my $mr = shift;
  foreach my $m ( sort { $b <=> $a } keys %$mr )
  {
    printf(" mask = 0x%X;\n", $m);
    printf(" switch(value & mask) {\n");
    my $ar = $mr->{$m};
    my %used;
# print Dumper($ar);
    foreach my $v ( @$ar )
    {
#      next if exists $used{ $v->[1] };
      $used{ $v->[1] }++;
      printf(" case 0x%X:\n", $v->[1]);
      # replace / with _
      my $ename = $v->[0];
      $ename =~ s/\//_/g;
      printf("  op = sw64_%s;\n", $ename);
      printf("  ops = 0x%X;\n", $v->[2]);
      printf("  return 1;\n");
    }
    printf(" }\n");
  }
print<<FOOT;
 return 0;
}
FOOT
}

sub real_7c
{
  my $name = shift;
  return ($name eq 'sextl' or
          $name eq 'negw'  or
          $name eq 'negl' or
          $name eq 'not'
  );
}


# main
my $status = getopts("dv");
if ($status == 0)
{
  HELP_MESSAGE();
}
my($str, $fp, $name, $mask, $value, $ops, %u, @names, %m, %used);
my $fname = 'opcodes';
$fname = $ARGV[0] if ( $#ARGV != -1 );
open($fp, '<', $fname) or die("cannot open $fname, error $!\n");
dump_header();
while($str = <$fp>)
{
  chomp $str;
  #            1 name  2 value    3 mask      4 - family?   5 - ops
  if ( $str !~ /^(\S+) ([0-9a-f]+) ([0-9a-f]+) ([0-9a-f]+) ([0-9a-f]+)$/i )
  {
    printf("bad str %s\n", $str);
    next;
  }
  $name = $1;
  $value = hex($2);
  $mask = hex($3);
  $ops = hex($5);
  # check if we already have such instruction
  my $guts = substr($str, length($name) + 1);
  if ( exists $used{$guts} )
  {
    printf("// %s and %s the same\n", $name, $used{$guts}) if ( defined $opt_v );
    next;
  } else {
    $used{$guts} = $name;
  }
  # black magic
## printf("%s %X ops %X mask %X\n", $name, $value, $ops, $mask);
  if ( is_za($ops) )
  {
    $value = insert_za($value);
    $mask = insert_za($mask);
    $ops = clear_za($ops);
  }
## printf("after za ops %X mask %X\n", $ops, $mask);
  if ( is_zb($ops) || is_fzb($ops) )
  {
    $value = insert_zb($value);
    $mask = insert_zb($mask);
    $ops = clear_zb($ops);
  }
## printf("after zb ops %X mask %X\n", $ops, $mask);
  if ( is_zc($ops) )
  {
    my $za = get_za($ops);
    # SW64_BPF_OPCODE_CMP_REG	0x10
    my $op = $value >> 26;
    # check op
    if ( $op == 0x10 )
    {
      if ( $za != 0xf || real_7c($name) )
      {
        $value = insert_zc($value);
        $mask = insert_zc($mask);
        $ops = clear_zc($ops);
## printf("%s zc 10 ops %X mask %X\n", $name, $ops, $mask);
      } elsif ( ($ops & 0x2ff) != 0x207 )
      {
        $value = insert_zc($value);
        $mask = insert_zc($mask);
        $ops = clear_zc($ops);
      }
    } elsif ( $op == 0x12 )
    {  # for SW64_BPF_OPCODE_ALU_IMM zc actually means zc and zb
        $value = insert_zb($value);
        $mask = insert_zb($mask);
        $ops = clear_zc($ops);
        $ops = clear_zb($ops);
## printf("zc 12 ops %X mask %X\n", $ops, $mask);
    } else {
#       printf("*** %s value %X mask %X ops %X\n", $name, $value, $mask, $ops);
      $value = insert_zc($value);
      $mask = insert_zc($mask);
      $ops = clear_zc($ops);
## printf("zc ops %X mask %X\n", $ops, $mask);
    }
  }
  # dirty hack for ldi/ldih
  if ( $name eq 'ldi' or $name eq 'ldih' )
  {
    next if ( ($ops >> 16) == 0xa );
  }
  if ( !exists $u{$name} )
  {
    $u{$name}++;
    push @names, [ $name, $ops ];
  }
  # collect [ name, value, $ops ]
  if ( !exists $m{$mask} )
  {
    $m{$mask} = [ [ $name, $value, $ops ] ];
  } else {
    my $ar = $m{$mask};
    push @$ar, [ $name, $value, $ops ];
  }
}
close $fp;
dump_enum(\@names);
dump_opnames(\@names);
dump_decode(\%m);