#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include <des.h>

MODULE = Des		PACKAGE = Des		PREFIX = des_

des_cblock
des_string_to_key(str)
	char *		str
    CODE:
	des_string_to_key(str, RETVAL);
    OUTPUT:
	RETVAL

des_key_schedule
des_set_key(key)
	des_cblock *		key
    CODE:
	des_set_key(key, RETVAL);
    OUTPUT:
	RETVAL

void
des_pcbc_encrypt(input, output, schedule, ivec)
	des_cblock *		input = NO_INIT
	SV *			output
	struct des_ks_struct *	schedule
	des_cblock *		ivec
	STRLEN			input_len = NO_INIT
	STRLEN			schedule_len = NO_INIT
	STRLEN			output_len = NO_INIT
    CODE:
	input = (des_cblock *) SvPV(ST(0), input_len);
	if (output == &sv_undef)
	    output = sv_newmortal();
	/*
	 * We replicate most of sv_setpvn so as to avoid crypting the
	 * data into a temporary buffer and then moving it to an SV
	 */
	if (!SvUPGRADE(output, SVt_PV))
	    croak("cannot use output argument as lvalue");
	output_len = (input_len + 7) & ~(STRLEN)7; /* round up to mult of 8 */
	(void) des_pcbc_encrypt(input, SvGROW(output, (I32) output_len + 1),
				(long) input_len, schedule, ivec, 1);
	SvCUR_set(output, output_len);
	*SvEND(output) = '\0';
	(void) SvPOK_only(output);
	SvTAINT(output);
	ST(0) = output;

void
des_pcbc_decrypt(input, output, schedule, ivec)
	des_cblock *		input = NO_INIT
	SV *			output
	struct des_ks_struct *	schedule
	des_cblock *		ivec
	STRLEN			input_len = NO_INIT
	STRLEN			ivec_len = NO_INIT
    CODE:
	input = (des_cblock *) SvPV(ST(0), input_len);
	if (input_len % 8)
	    croak("DES ciphertext must be an integral multiple of 8 bytes");
	if (output == &sv_undef)
	    output = sv_newmortal();
	/*
	 * We replicate most of sv_setpvn so as to avoid crypting the
	 * data into a temporary buffer and then moving it to an SV
	 */
	if (!SvUPGRADE(output, SVt_PV))
	    croak("cannot use output argument as lvalue");
	(void) des_pcbc_encrypt(input, SvGROW(output, (I32) input_len),
			 (long) input_len, schedule, ivec, 0);
	SvCUR_set(output, input_len);
	*SvEND(output) = '\0';
	(void) SvPOK_only(output);
	SvTAINT(output);
	ST(0) = output;

void
des_cbc_encrypt(input, output, schedule, ivec)
	des_cblock *		input = NO_INIT
	SV *			output
	struct des_ks_struct *	schedule
	des_cblock *		ivec
	STRLEN			input_len = NO_INIT
	STRLEN			output_len = NO_INIT
    CODE:
	input = (des_cblock *) SvPV(ST(0), input_len);
	if (output == &sv_undef)
	    output = sv_newmortal();
	/*
	 * We replicate most of sv_setpvn so as to avoid crypting the
	 * data into a temporary buffer and then moving it to an SV
	 */
	if (!SvUPGRADE(output, SVt_PV))
	    croak("cannot use output argument as lvalue");
	output_len = (input_len + 7) & ~(STRLEN)7; /* round up to mult of 8 */
	(void) des_cbc_encrypt(input, SvGROW(output, (I32) output_len + 1),
				(long) input_len, schedule, ivec, 1);
	SvCUR_set(output, output_len);
	*SvEND(output) = '\0';
	(void) SvPOK_only(output);
	SvTAINT(output);
	ST(0) = output;

void
des_cbc_decrypt(input, output, schedule, ivec)
	des_cblock *		input = NO_INIT
	SV *			output
	struct des_ks_struct *	schedule
	des_cblock *		ivec
	STRLEN			input_len = NO_INIT
	STRLEN			ivec_len = NO_INIT
    CODE:
	input = (des_cblock *) SvPV(ST(0), input_len);
	if (input_len % 8)
	    croak("DES ciphertext must be an integral multiple of 8 bytes");
	if (output == &sv_undef)
	    output = sv_newmortal();
	/*
	 * We replicate most of sv_setpvn so as to avoid crypting the
	 * data into a temporary buffer and then moving it to an SV
	 */
	if (!SvUPGRADE(output, SVt_PV))
	    croak("cannot use output argument as lvalue");
	(void) des_cbc_encrypt(input, SvGROW(output, (I32) input_len),
			 (long) input_len, schedule, ivec, 0);
	SvCUR_set(output, input_len);
	*SvEND(output) = '\0';
	(void) SvPOK_only(output);
	SvTAINT(output);
	ST(0) = output;

des_cblock
des_ecb_encrypt(input, schedule)
	des_cblock *		input
	struct des_ks_struct *	schedule
    CODE:
	(void) des_ecb_encrypt(input, (des_cblock *)&(RETVAL[0]), schedule, 1);
    OUTPUT:
	RETVAL

des_cblock
des_ecb_decrypt(input, schedule)
	des_cblock *		input
	struct des_ks_struct *	schedule
    CODE:
	(void) des_ecb_encrypt(input, (des_cblock *)&(RETVAL[0]), schedule, 0);
    OUTPUT:
	RETVAL

des_cblock
des_cbc_cksum(input, schedule, ivec)
	des_cblock *		input = NO_INIT
	struct des_ks_struct *	schedule
	des_cblock *		ivec
	STRLEN			input_len = NO_INIT
    CODE:
	input = (des_cblock *) SvPV(ST(0), input_len);
	(void) des_cbc_cksum(input, (des_cblock *)&(RETVAL[0]),
			     (long) input_len, schedule, ivec);
    OUTPUT:
	RETVAL

des_cblock
des_random_key()
    CODE:
	(void) des_random_key((des_cblock *)&(RETVAL[0]));
    OUTPUT:
	RETVAL

des_cblock
des_read_password(prompt, verify = 0)
	char *	prompt
	int	verify
    CODE:
	if (des_read_password((des_cblock *)&(RETVAL[0]), prompt, verify))
	    croak("Des::des_read_password failed to read password");
    OUTPUT:
	RETVAL
