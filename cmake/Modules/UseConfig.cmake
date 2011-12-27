# Manage oscam-config.h based on command line parameters

# Manipulate config file based on given parameters and read unset parameters
MACRO(GENERATE_OSCAM_CONFIG dirname scriptname configname)
	file(READ "${dirname}/${scriptname}" script)
	string(REGEX REPLACE ";" "\\\\;" script "${script}")
	string(REGEX REPLACE "\n" ";" script "${script}")
	foreach(line ${script})
		if("${line}" MATCHES "^addons=.*")
			string(LENGTH ${line} length)
			MATH(EXPR length "${length} - 9") 
			string(SUBSTRING ${line} 8 ${length} addons)
			string(REGEX REPLACE " " ";" addons "${addons}")
		elseif("${line}" MATCHES "^protocols=.*")
			string(LENGTH ${line} length)
			MATH(EXPR length "${length} - 12") 
			string(SUBSTRING ${line} 11 ${length} protocols)
			string(REGEX REPLACE " " ";" protocols "${protocols}")
		elseif("${line}" MATCHES "^readers=.*")
			string(LENGTH ${line} length)
			MATH(EXPR length "${length} - 10") 
			string(SUBSTRING ${line} 9 ${length} readers)
			string(REGEX REPLACE " " ";" readers "${readers}")
		endif("${line}" MATCHES "^addons=.*")
	endforeach(line)

	file(READ "${dirname}/${configname}" config)
	foreach(option ${addons} ${protocols} ${readers})
		if(DEFINED ${option})
			# Note: cmake does not read the file as individual lines but as a long
			#		string, hence we use \n instead of ^ to determine where a line begins

			if(${option})
				string(REGEX REPLACE "\n//#define ${option}\n" "\n#define ${option}\n" config ${config})
			else(${option})
				string(REGEX REPLACE "\n#define ${option}\n" "\n//#define ${option}\n" config ${config})
			endif(${option})
		else(DEFINED ${option})
			# read value from current oscam-config.h

			if(${config} MATCHES "\n#define ${option}\n")
				SET(${option} TRUE)
			endif(${config} MATCHES "\n#define ${option}\n")
		endif(DEFINED ${option})
	endforeach(option)
	file(WRITE "${dirname}/${configname}" ${config})
ENDMACRO(GENERATE_OSCAM_CONFIG fullpath)
