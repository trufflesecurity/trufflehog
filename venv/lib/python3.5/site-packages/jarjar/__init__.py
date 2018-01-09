from sys import version_info as _version_info

# different importing for python 2 and 3
if _version_info.major == 2:
	from jarjar import jarjar
else:
	from jarjar.jarjar import jarjar