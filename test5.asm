    .text
    lw      $s1,0($gp)
    lw      $s2,1($gp)
    addu    $a0,$s1,$s2        
    addiu   $v0,$zero,1        
    syscall
    addiu   $v0,$zero,10        # exit
    syscall
    .data
n:  .word   10
m:  .word   100
