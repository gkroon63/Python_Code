#!/usr/bin/python
########################################################################################################################
#
# Licensed Materials - Property of CLS
#
# (C) COPYRIGHT CLS UK Ltd.
# All Rights Reserved
#
# COMPONENT_NAME: dyn_custom_disk_metrics.py
#
# ORIGINS: CLS Service Operations UK
#
# This script is written to create, modify or remove Dynatrace Custome Disk
# events in bulk. 
#
# Revision History:
#
# Date        Version  By                  Details
# ==========================================================
# 13-Jul-2021 1.0      Glen Kroon          Initial Revision
#
#####################################################################################################################

import requests
import sys, getopt
sys.path.insert(1, '/cls/svcops/infra/scripts')
import dyn_api_token
import os
import json

metric_action = ""
fname = ""
progname = ""
prog_version = 1.0
debug = 0
dynapi_token = dyn_api_token.get_token()

def parseargs(argv):
	#print("Argument Length", len(sys.argv), progname)
	usage = "USAGE: " + progname + " -h|--help|-v|--version|-c|--create|-r|--remove|-m|--modify -f|--filename FILENAME"
	if len(sys.argv) < 2:
		print("")
		print(usage)
		print("")	
		arg_results = 1, 0
		return arg_results
	elif (len(sys.argv) > 1) and (len(sys.argv) < 5): 
		fname = "x"
		try:
			opts, args = getopt.getopt(argv,"vhcrmf:",["help","create","remove","modify","filename="])
		except getopt.GetoptError:
			print("")
			print(usage)
			print("")	
			sys.exit(2)
		for opt, arg in opts:
			if opt in ("-h", "--help"):
				print_usage(usage)
				sys.exit(0)
			if opt in ("-v", "--version"):
				print("")
				print(progname + " Version: " + str(prog_version))
				print("")	
				sys.exit(0)
			elif opt in ("-c", "--create"):
				metric_action = "create"
			elif opt in ("-r", "--remove"):
				metric_action = "remove"
			elif opt in ("-m", "--modify"):
				metric_action = "modify"
			elif opt in ("-f", "--filename"):
				fname = arg
				if not os.path.isfile(fname):
					print("")
					print("Filename: " + fname + " does not exist. Please check and try again.")
					print("")
					sys.exit(1)
		arg_results = metric_action, fname
		return arg_results
	else:
		print("")
		print(usage)
		print("")	
		arg_results = 1, 0
		return arg_results


def validate_file_entries(metric_action, fname):
	stat = 0
	metric_name = ""
	try:
		with open(fname, "r") as mfin:
			for metline in mfin:
				metline = metline.strip()
				if metline.startswith('#'):
					pass
				else:
					x = metline.split(":")
					if len(x) >= 6 and metric_action == "create":
						print("")
						print("Validating metric name: " + str(x[0]) + "..."),
						dynapi_token = dyn_api_token.get_token()
						if dyn_api_token.get_disk_event(dynapi_token, "anomalyDetection/diskEvents", "name", str(x[0])):
							print(" Failed. Metric name already exists")
							stat = 1
						else:
							print(" Passed.")
						print("Validating metric for: " + str(x[0]) + "..."),
						if x[1] == "LOW_DISK_SPACE":
							print(x[1] + " Passed.")
						elif x[1] == "LOW_INODES":
							print(x[1] + " Passed.")
						else:
							print(x[1] + " Failed.")
							stat = 1
						print("Validating Threshold for: " + str(x[0]) + "..."),
						if isinstance(float(x[2]), float):
							print(x[2] + " Passed.")
						else:
							print(x[2] + " Failed.")
							stat = 1
						print("Validating Samples for: " + str(x[0]) + "..."),
						if isinstance(int(x[3]), int):
							print(x[3] + " Passed.")
						else:
							print(x[3] + " Failed.")
							stat = 1
						print("Validating ViolatingSamples for: " + str(x[0]) + "..."),
						if isinstance(int(x[4]), int):
							print(x[4] + " Passed.")
						else:
							print(x[4] + " Failed.")
							stat = 1
						if int(x[4]) > int(x[3]):
							print("ViolatingSamples: " + str(x[4]) + " is greater than Samples: " + str(x[3]))
							stat = 1
						print("Validating FilterOperator for: " + str(x[0]) + "..."),
						if x[5] == "EQUALS":
							print(x[5] + " Passed.")
						elif x[5] == "CONTAINS":
							print(x[5] + " Passed.")
						else:
							print(x[5] + " Failed.")
							stat = 1
						print("Validating FilterValue for: " + str(x[0]) + "..."),
						if isinstance(x[6], str):
							print(x[6] + " Passed.")
						else:
							print(x[6] + " Failed.")
							stat = 1
					elif len < 7 and metric_action == "modify":
						pass
					elif len > 1 and metric_action == "remove":
						print("")
						print("Validating metric name: " + str(x[0]) + "..."),
						dynapi_token = dyn_api_token.get_token()
						if dyn_api_token.get_disk_event(dynapi_token, "anomalyDetection/diskEvents", "name", str(x[0])):
							print(" Passed.")
						else:
							print(" Failed. Metric name does not exist")
							stat = 1
					else:
						print("")
						print("File: " + fname + " is not in expected format for the action: " + "\"" + metric_action + "\".")
						print("Please validate and try again.")
						print("")
						mfin.close()
						os._exit(1)
	finally:
		print("")
		mfin.close()	
		return stat

def process_file(metric_action, fname):
	try:
		print("")
		with open(fname, "r") as mfin:
			for metline in mfin:
				element_count = 0
				metline = metline.strip()
				if metline.startswith('#'):
					pass
				else:
					x = metline.split(":")
					if len(x) >= 6 and metric_action == "create":
						print("Processing metric: " + str(x[0]) + "... "),
						lof = len(x)
						current_pid = os.getpid()
						progtemp = progname.split('.')
						tempfile = "/var/tmp/" + progtemp[0] + "." + str(current_pid)
						tfh = open(tempfile, 'w+')
						tfh.write("{")	
						tfh.write("  \"name\": " + "\"" + x[0] + "\"" + ",")	
						tfh.write("  \"enabled\": " + "true" + ",")	
						tfh.write("  \"metric\": " + "\"" + x[1] + "\"" + ",")	
						tfh.write("  \"threshold\": " + str(x[2]) + ",")	
						tfh.write("  \"samples\": " + str(x[3]) + ",")	
						tfh.write("  \"violatingSamples\": " + str(x[4]) + ",")	
						tfh.write("  \"diskNameFilter\": " + "{")	
						tfh.write("  \"operator\": " + "\"" + str(x[5]) + "\"" + ",")	
						tfh.write("  \"value\": " + "\"" + str(x[6]) + "\"")	
						tfh.write("  }" + ",")	
						if len(x) > 7:
							tfh.write("  \"tagFilters\": " + "[")	
							tfh.write("    {")	
							for i in range(7, lof):
								if (i % 2) == 1:
									if x[i] == "null":
										tfh.write(" \"value\": " + "null" + ",")	
									else:
										tfh.write(" \"value\": " + "\"" + x[i] + "\"" + ",")	
								else:
									tfh.write(" \"key\": " + "\"" + x[i] + "\"" + ",")	
									tfh.write(" \"context\": " + "\"" + "ENVIRONMENT" + "\"")	
									if i == (lof - 1):	
										tfh.write(" }")	
									else:
										tfh.write(" }" + ",")	
							tfh.write("  ]")	
						else:
							tfh.write("  \"tagFilters\": " + "[]")	
						tfh.write("}")	
						tfh.flush()
						tfh.seek(0)
						jdisk_event_detail = tfh.read()
						jdisk_event_detail = jdisk_event_detail.replace(" ", "")
						jdisk_event_detail = jdisk_event_detail.strip()
						if debug:
							print("\n" + jdisk_event_detail + "\n")
						stat = dyn_api_token.create_dyn_obj(dynapi_token, "anomalyDetection/diskEvents", jdisk_event_detail)
						if stat == 201:
							print("Completed Successfuly. " + "Response Code: " + str(stat))
						else:
							print("Failed. " + "Response Code: " + str(stat))
						tfh.close()
						os.remove(tempfile)
					elif len < 8 and metric_action == "modify":
						pass
					elif len > 1 and metric_action == "remove":
						print("Removing metric: " + str(x[0]) + "... "),
						event_id = dyn_api_token.get_disk_event_id(dynapi_token, "anomalyDetection/diskEvents", str(x[0]))
						if event_id is not None:
							stat = dyn_api_token.delete_dyn_obj(dynapi_token, "anomalyDetection/diskEvents", event_id)	
						if stat == 204:
							print("Completed Successfuly. " + "Response Code: " + str(stat))
						else:
							print("Failed. " + "Response Code: " + str(stat))
					else:
						print("")
						print("File: " + fname + " is not in expected format for the action: " + "\"" + metric_action + "\".")
						print("Please validate and try again.")
						print("")
						mfin.close()
						os._exit(1)
	finally:
		print("")
		mfin.close()	

def print_usage(usage):
	print("""
=================================================================================
                                 HELP SECTION
=================================================================================
""")
	print("                                 Version: " + str(prog_version))
	print("""
       CLS Service Operations Dynatrace Custom Disk Event Maintenance Script             

This script was written to alleviate the laborious task of having to create custom
disk events in bulk through the Dynatrace SaaS Portal from the browser interface.
This script will accept a pre-formatted text file for the creation, modification
or removal of custom disk events in Dynatrace.
""")
	print(usage)
	print("\nwhere:")
	print("""
-h|--help: This section

-v|--version: Current Version

-c|--create: Create Dynatrace Custom Disk Event(s).

-m|--modify: Modify an existing Dynatrace Custom Disk Event(s).

-r|--remove: Removes an existing Dynatrace Custom Disk Event(s).

-f|--filename: The file containng the list of custom disk details to be created, modified or removed

Format of File(Colon(:) Seperated):

Creating Custom Disk Events:

Name of metric:metric:Threshold:Samples:ViolatingSamples:FilterOperator:FilterValue:TagFilterValue:TagfilterKey

There can be as many Tag filters following the field 'FilterValue'

Example Format for creating a custom disk event:
unxinf_os_root:LOW_DISK_SPACE:5.0:5:3:EQUALS:/usr:null:LinInf_UnixOS

Modifying Custom Disk Events:

To be implemented

Removing Custom Disk Events:

Name of metric:

Example Format for removing a custom disk event:
unxinf_os_root:
""")

def main(argv):
	arg_results = parseargs(argv)
	metric_action = arg_results[0]
	fname = arg_results[1]
	if metric_action == "create" and fname is not None:
		if validate_file_entries(metric_action, fname) == 0:
			process_file(metric_action, fname)
			os._exit(0)
		else:
			os._exit(1)
	elif metric_action == "remove":
		if validate_file_entries(metric_action, fname) == 0:
			process_file(metric_action, fname)
			os._exit(0)
		else:
			os._exit(1)
	elif metric_action == "modify":
		print("")
		print("Yet to be implemented.")
		print("")
		os._exit(0)
	else:
		os._exit(metric_action)

if __name__ == "__main__":
	progname = os.path.basename(sys.argv[0])
	main(sys.argv[1:])	
