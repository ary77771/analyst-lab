"""A fixture lab that is broken ON PURPOSE: it fails while it is loaded, as a lab with a mistake at its top
level would. The dashboard must leave it out, say why, and go on with everything else."""
raise RuntimeError("this lab is broken on purpose")
