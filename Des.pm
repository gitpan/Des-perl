package Des;
require Exporter;
require DynaLoader;
@ISA = (Exporter, DynaLoader);

@EXPORT =	qw(string_to_key set_key pcbc_encrypt pcbc_decrypt
		cbc_encrypt cbc_decrypt ecb_encrypt ecb_decrypt cbc_cksum);
@EXPORT_OK =	qw(random_key read_password);

bootstrap Des;

1;
