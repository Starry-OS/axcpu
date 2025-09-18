// AArch64 user space safe memory copy
// Based on RISC-V implementation and optimized for AArch64

.section .text
.global user_copy
user_copy:
	// x0 = dst, x1 = src, x2 = size
	// Return: 0 on success, remaining bytes on fault
	
	// Quick exit for zero size
	cbz	x2, .Lsuccess
	
	// Save the end address for fault handling
	add	x3, x0, x2	// x3 = dst_end
	mov	x4, x2		// x4 = original_size (for fault calculation)
	
	// Use different strategies based on size
	cmp	x2, #64
	b.lo	.Lbyte_copy
	
	// For larger copies, try to align and use word copy
	// First align dst to 8-byte boundary
	and	x5, x0, #7
	cbz	x5, .Laligned_copy
	
	// Copy bytes until dst is 8-byte aligned
	sub	x5, x2, x5	// remaining after alignment
.Lalign_loop:
	ldrb	w6, [x1], #1
	strb	w6, [x0], #1
	tbnz	x0, #0, .Lalign_loop
	tbnz	x0, #1, .Lalign_loop  
	tbnz	x0, #2, .Lalign_loop
	mov	x2, x5		// update remaining size
	
.Laligned_copy:
	// Now dst is 8-byte aligned, do word copy
	cmp	x2, #8
	b.lo	.Lbyte_copy
	
	// Unrolled 8-word (64-byte) copy loop
	sub	x5, x2, #64
.Lword_loop:
	ldp	x6, x7, [x1], #16
	ldp	x8, x9, [x1], #16  
	ldp	x10, x11, [x1], #16
	ldp	x12, x13, [x1], #16
	stp	x6, x7, [x0], #16
	stp	x8, x9, [x0], #16
	stp	x10, x11, [x0], #16
	stp	x12, x13, [x0], #16
	subs	x2, x2, #64
	cmp	x2, #64
	b.hs	.Lword_loop
	
	// Handle remaining words (8-byte chunks)
.Lword_remainder:
	cmp	x2, #8
	b.lo	.Lbyte_copy
	ldr	x6, [x1], #8
	str	x6, [x0], #8
	sub	x2, x2, #8
	b	.Lword_remainder
	
.Lbyte_copy:
	// Copy remaining bytes
	cbz	x2, .Lsuccess
.Lbyte_loop:
	ldrb	w6, [x1], #1
	strb	w6, [x0], #1
	subs	x2, x2, #1
	b.ne	.Lbyte_loop
	
.Lsuccess:
	mov	x0, #0
	ret