#
# Copyright (C) 2011-2012 Free Software Foundation, Inc.
#
# Author: Nikos Mavrogiannopoulos
#
# This file is part of GnuTLS.
#
# The GnuTLS is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License
# as published by the Free Software Foundation; either version 3 of
# the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# *** This file is auto-generated ***
#
.file	"devel/perlasm/cpuid-x86.s"
.text
.globl	_gnutls_cpuid
.align	4
_gnutls_cpuid:
L_gnutls_cpuid_begin:
	pushl	%ebp
	movl	%esp,%ebp
	subl	$12,%esp
	movl	%ebx,(%esp)
	movl	8(%ebp),%eax
	movl	%esi,4(%esp)
	movl	%edi,8(%esp)
	pushl	%ebx
	.byte	0x0f,0xa2
	movl	%ebx,%edi
	popl	%ebx
	movl	%edx,%esi
	movl	12(%ebp),%edx
	movl	%eax,(%edx)
	movl	16(%ebp),%eax
	movl	%edi,(%eax)
	movl	20(%ebp),%eax
	movl	%ecx,(%eax)
	movl	24(%ebp),%eax
	movl	%esi,(%eax)
	movl	(%esp),%ebx
	movl	4(%esp),%esi
	movl	8(%esp),%edi
	movl	%ebp,%esp
	popl	%ebp
	ret
.globl	_gnutls_have_cpuid
.align	4
_gnutls_have_cpuid:
L_gnutls_have_cpuid_begin:
	pushfl
	popl	%eax
	orl	$2097152,%eax
	pushl	%eax
	popfl
	pushfl
	popl	%eax
	andl	$2097152,%eax
	ret
.byte	67,80,85,73,68,32,102,111,114,32,120,56,54,0
