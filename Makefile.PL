use ExtUtils::MakeMaker;
WriteMakefile(LIBS => ["-ldes"],
	      INC => "-I/usr/local/include");
