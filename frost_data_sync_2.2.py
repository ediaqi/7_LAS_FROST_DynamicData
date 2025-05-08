import sys, os 
from parameters import read_param
import base64, datetime, hashlib, hmac 
import requests 
import csv
import calendar
import json
from requests.exceptions import HTTPError
import pandas as pd
from requests.auth import HTTPBasicAuth
from datetime import timedelta
from datetime import datetime

try:
    #Reading configuration parameters
	print ('Number of arguments:', len(sys.argv), 'arguments.', flush = True)
	print ('Argument List:', str(sys.argv), '\n', flush = True)
    
	deltaT = int(sys.argv[1])
	if deltaT <= 0:
		print ('Argomento specificato non valido \n', flush = True)
		sys.exit()
	#print('deltaT', deltaT, flush = True)
	deltaT = timedelta(days=deltaT)
	print('Lettura dei configuration parameters...\n', flush = True)
	aws_params = read_param('data/parameters.ini', 'aws_credentials')
	frost = read_param('data/parameters.ini', 'frost')
	files = read_param('data/parameters.ini', 'files')
	
	log_csv  = files.get('log_path') + files.get('log_filename')
	log_csv_path = files.get('log_path')
	#print(log_csv)
	log_filename = files.get('log_filename')
	log_inserimenti_filename = files.get('log_frost_filename')
	#print(log_inserimenti_filename)
	datastream_csv_path = files.get('mapping_path') + files.get('mapping_filename')
	datastream_filename = files.get('mapping_filename')
	#print(datastream_csv_path)
	resultTime_path = files.get('mapping_path') 
    
	access_key  = aws_params.get('aws_access_key_id')
	secret_key = aws_params.get('aws_secret_access_key')
	access_API_key  = frost.get('username')
	secret_API_key = frost.get('password')
	access_API_key_r  = frost.get('username_read')
	secret_API_key_r = frost.get('password_read')    
	base_url = frost.get('server_url')
	    
	current_time = datetime.utcnow()
	current_time_str = current_time.strftime('%Y-%m-%dT%H:%M:%SZ') #!!verifica
	
	resultTime_txt = resultTime_path + '{}.txt'.format(current_time_str)
	#print(resultTime_txt, flush = True)
	now = current_time.replace(minute=0, second=0, microsecond=0)
	now_str = now.strftime('%Y-%m-%dT%H:%M:%SZ')
	#print(now, flush = True)
	print('Now:',now_str, '\n', flush = True)
    
	timestamp = ''
    
	with open(resultTime_txt, 'w', newline='') as txtfile:
		print(f"Il file txt '{current_time_str}' è stato creato.\n", flush = True)
       

    #Controlli vari:
	status = f'WARNING: alcuni passaggi non sono andati a buon fine, verificare nel file <{log_inserimenti_filename}> e <{current_time_str}.txt>'
	if files.get('log_path') == '' or files.get('log_filename') == '':
		esito = 'Nessun path specificato per il file log.csv\n'
		print(f"Esecuzione script interrotta\n", flush = True)
		with open(resultTime_txt, 'a', newline='') as txtfile:
			txtfile.write(esito)
		with open(log_csv, 'a', newline='') as csvfile:
			csvwrite = csv.writer(csvfile)
			csvwrite.writerow(([current_time_str,timestamp,status]))
		sys.exit()
	if files.get('log_frost_filename') == '':
		esito = 'Nessun path specificato per il file log_inserimenti.csv\n'
		print(f"Esecuzione script interrotta\n", flush = True)        
		with open(resultTime_txt, 'a', newline='') as txtfile:
			txtfile.write(esito)
		with open(log_csv, 'a', newline='') as csvfile:
			csvwrite = csv.writer(csvfile)
			csvwrite.writerow(([current_time_str,timestamp,status]))
		sys.exit()
	if files.get('mapping_path') == '' or files.get('mapping_filename') == '':
		print(f"Esecuzione script interrotta\n", flush = True)
		esito = 'Nessun path specificato per il file datastreams.csv\n'
		with open(resultTime_txt, 'a', newline='') as txtfile:
			txtfile.write(esito)
		with open(log_csv, 'a', newline='') as csvfile:
			csvwrite = csv.writer(csvfile)
			csvwrite.writerow(([current_time_str,timestamp,status]))	  
		sys.exit()
	if access_key == '' or secret_key == '':
		print(f"Esecuzione script interrotta\n", flush = True)
		esito = 'Non è disponibile alcuna chiave di accesso per AWS\n'
		with open(resultTime_txt, 'a', newline='') as txtfile:
			txtfile.write(esito)
		with open(log_csv, 'a', newline='') as csvfile:
			csvwrite = csv.writer(csvfile)
			csvwrite.writerow(([current_time_str,timestamp,status]))
		sys.exit()
	if access_API_key == '' or secret_API_key == '':
		print(f"Esecuzione script interrotta\n", flush = True)
		esito = 'Non è disponibile alcuna chiave di accesso per FROST\n'
		with open(resultTime_txt, 'a', newline='') as txtfile:
			txtfile.write(esito)
		with open(log_csv, 'a', newline='') as csvfile:
			csvwrite = csv.writer(csvfile)
			csvwrite.writerow(([current_time_str,timestamp,status]))
		sys.exit()
	if base_url == '':
		print(f"Esecuzione script interrotta\n", flush = True)
		esito = 'Nessun server url specificato per FROST\n'
		with open(resultTime_txt, 'a', newline='') as txtfile:
			txtfile.write(esito)
		with open(log_csv, 'a', newline='') as csvfile:
			csvwrite = csv.writer(csvfile)
			csvwrite.writerow(([current_time_str,timestamp,status]))
		sys.exit()
        
	if access_API_key_r == '' or secret_API_key_r == '':
		print(f"Esecuzione script interrotta\n", flush = True)
		esito = 'Non è disponibile alcuna chiave di accesso per lettura in FROST\n'
		with open(resultTime_txt, 'a', newline='') as txtfile:
			txtfile.write(esito)
		with open(log_csv, 'a', newline='') as csvfile:
			csvwrite = csv.writer(csvfile)
			csvwrite.writerow(([current_time_str,timestamp,status]))
		sys.exit()
	intervals = []

    
	print('Lettura dei configuration parameters andata a buon fine!\n', flush = True)
	with open(resultTime_txt, 'a', newline='') as txtfile:
		txtfile.write('Lettura dei configuration parameters andata a buon fine!\n')
	print('Istante di esecuzione dello script:',  current_time_str, '\n', flush= True) 

	#---------------------------------------------------------------------------------
	#Request API
	method = 'GET'
	service = 'execute-api'
	host = '2fgy9ddyeg.execute-api.eu-west-1.amazonaws.com'
	region = 'eu-west-1'
	endpoint = 'https://2fgy9ddyeg.execute-api.eu-west-1.amazonaws.com/Ediaqi/data'
	
	
	def sign(key, msg):
	    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()
	
	def getSignatureKey(key, dateStamp, regionName, serviceName):
		kDate = sign(('AWS4' + key).encode('utf-8'), dateStamp)
		kRegion = sign(kDate, regionName)
		kService = sign(kRegion, serviceName)
		kSigning = sign(kService, 'aws4_request')
		return kSigning

    
#---------------------------------------------------------------------------------   
#Fare in modo che il log venga creato al primo utilizzo
				
	if not os.path.exists(log_csv):
		with open(log_csv, 'w', newline='') as csvfile:
			csvwrite = csv.writer(csvfile)
			csvwrite.writerow(["ResultTime", "PhenomenonTime", "Status"])
			print(f"Il file CSV '{log_filename}' è stato creato.\n", flush = True)
	else:
			with open(resultTime_txt, 'a', newline='') as txtfile:
				txtfile.write(f"Il file CSV '{log_filename}' è stato trovato.\n")
			print(f"Il file CSV '{log_filename}' esiste già al percorso '{log_csv_path}'." + "\n", flush = True)
    
    
	log_inserimenti = log_csv_path + '/{}'.format(log_inserimenti_filename)
	
	if not os.path.exists(log_inserimenti):
		with open(log_inserimenti, 'w', newline='') as csvfile:
			csvwrite = csv.writer(csvfile)
			csvwrite.writerow(["ResultTime", "PhenomenonTime", "ThingID", "HTTPResponse", "ObservationCount"])
			print(f"Il file CSV '{log_inserimenti_filename}' è stato creato.\n", flush = True)
	else:
			with open(resultTime_txt, 'a', newline='') as txtfile:
				txtfile.write(f"Il file CSV '{log_inserimenti_filename}' è stato trovato.\n")
			print(f"Il file CSV '{log_inserimenti_filename}' esiste già al percorso '{log_csv_path}'." + "\n", flush = True)
            
    #Lo script deve leggere l'ultima riga e l'intervallo orario lavorato e, se coincide con l'intervallo orario che si stava proponendo di richiedere, si blocca.
    
	if not os.path.exists(datastream_csv_path):
		with open(resultTime_txt, 'a', newline='') as txtfile:
			txtfile.write("ATTENZIONE! Il file di mapping '{}' non esiste al percorso specificato.\n".format(datastream_filename))
			print(f"Esecuzione script interrotta\n", flush = True)
		with open(log_csv, 'a', newline='') as csvfile:
			csvwrite = csv.writer(csvfile)
			csvwrite.writerow(([current_time_str,timestamp,status]))
			sys.exit()
	else:
			with open(resultTime_txt, 'a', newline='') as txtfile:
				txtfile.write(f"Il file CSV '{datastream_filename}' è stato trovato.\n")
			print(f"Il file di mapping '{datastream_filename}' esiste già al percorso '{datastream_csv_path}'." + "\n", flush = True)
    
    
	chunksize = 10000
	machineSN_observedProps_list = []

	for chunk in pd.read_csv(datastream_csv_path, chunksize=chunksize):
		machineSN_observedProps_list.append(chunk.groupby('ID Locale Sensore').agg(lambda x: x.tolist()))

	machineSN_observedProps = pd.concat(machineSN_observedProps_list)                
	df = pd.read_csv(datastream_csv_path)

	#machineSN_observedProps = df.groupby('ID Locale Sensore').agg(lambda x: x.tolist())

	#print(machineSN_observedProps, flush = True)
	#print("\n")
    
	status = 'OK'
	all_data_machineSN = []
    
	for machineSN, group_data in machineSN_observedProps.groupby('ID Locale Sensore'):
		for datastreamId in group_data['ID Datastream Frost'].explode().unique():
			#print(datastreamId)
			datastream_url =base_url + f'Datastreams({datastreamId})'
			#print(datastream_url, flush = True)
			response_ds = requests.get(datastream_url, auth=HTTPBasicAuth(access_API_key_r, secret_API_key_r))
			
			if response_ds.status_code == 200:
				data = response_ds.json()
				#print(data, flush = True)

				phenomenon_time = data.get('phenomenonTime', '').split('/')[-1]
				#print(phenomenon_time, flush = True)

				if phenomenon_time:
					#now = datetime(2024, 6, 9, 21, 30)
					last_observation_time = phenomenon_time
					current_start = datetime.strptime(last_observation_time, '%Y-%m-%dT%H:%M:%SZ')
					#current_start = datetime(2024, 6, 9, 21, 10)
					observation_interval = timedelta(minutes=5)
					#print(current_start, flush=True)
					while current_start < now:
						current_end = min(current_start + deltaT, now)
						intervals.append((datastreamId, current_start, current_end))
						current_start = current_end + observation_interval
					print(f"Last observation time for datastream {datastreamId}/{machineSN}: {last_observation_time}\n")
					with open(resultTime_txt, 'a', newline='') as txtfile:
						txtfile.write(f"Last observation time for datastream {datastreamId}/{machineSN}: {last_observation_time}\n")	                    
				else:
					print(f"Nessuna osservazione trovata per il datastream {datastreamId}/{machineSN}", flush=True)
					with open(resultTime_txt, 'a', newline='') as txtfile:
						txtfile.write(f"Nessuna osservazione trovata per il datastream {datastreamId}/{machineSN}\n")	                     
			else:
				print(f"Errore lettura dati Datastreams FROST: {response_ds.status_code}\n")
				with open(resultTime_txt, 'a', newline='') as txtfile:
					txtfile.write(f"Errore lettura dati Datastreams FROST: {response_ds.status_code}/{datastreamId}/{machineSN}\n")	                    
	#print(intervals, flush = True)
	print(f"Numero totale di intervalli creati: {len(intervals)}", flush=True)
	json_struct = []
	added_datastream_ids = set()
	temp_data = []
	obs_count = []

	for machineSN, group_data in machineSN_observedProps.groupby('ID Locale Sensore'):
		total_datastreams = len(group_data['ID Datastream Frost'].explode().unique())
		datastream_counter = 0
		print(f"Ciclo avviato per la machineSN: {machineSN}", flush = True)
		for int_datastreamId, interval_start, interval_end in intervals:
			#print(int_datastreamId, flush = True)
			#print(group_data['ID Datastream Frost'].values, flush = True)
			json_struct.clear()
			if int_datastreamId in group_data['ID Datastream Frost'].explode().values:
				datastream_counter += 1
				is_last_datastream = (datastream_counter == total_datastreams)
				observedProperty = group_data['ID Locale Proprieta Osservata'].tolist()
				print(f"Processing datastream {int_datastreamId} for interval {interval_start} to {interval_end}", flush=True)
				with open(resultTime_txt, 'a', newline='') as txtfile:
					txtfile.write(f"Processing datastream {int_datastreamId} for interval {interval_start} to {interval_end}\n")
				t = datetime.utcnow()
				amzdate = t.strftime('%Y%m%dT%H%M%SZ')
				datestamp = t.strftime('%Y%m%d') # Date w/o time, used in credential scope
				canonical_uri = '/Ediaqi/data' 
				#print("Request start", interval_start, flush = True)
				#print("Request end",interval_end, flush = True)
				interval_start_str = interval_start.strftime('%Y-%m-%d %H:%M:%S')
				interval_end_str = interval_end.strftime('%Y-%m-%d %H:%M:%S')
				timestamp = interval_start_str + '/' + interval_end_str
				timestampA = int(interval_start.timestamp())
				timestampB = int(interval_end.timestamp())
				request_parameters = f"machineSN={machineSN}&tsFrom={timestampA}&tsTo={timestampB}"
				#print(f"L'intervallo orario per il retrieve dei dati è {interval_start}/{interval_end} \n", flush = True)
            	
				#print(request_parameters, flush= True)
				#----------------------------------------------------------------------	
				canonical_querystring = request_parameters
				canonical_headers = 'host:' + host + '\n' + 'x-amz-date:' + amzdate + '\n'
				signed_headers = 'host;x-amz-date'
				payload_hash = hashlib.sha256(('').encode('utf-8')).hexdigest()
				canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash
				algorithm = 'AWS4-HMAC-SHA256'
				credential_scope = datestamp + '/' + region + '/' + service + '/' + 'aws4_request'
				string_to_sign = algorithm + '\n' +  amzdate + '\n' +  credential_scope + '\n' +  hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
				signing_key = getSignatureKey(secret_key, datestamp, region, service)
				signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()
				authorization_header = algorithm + ' ' + 'Credential=' + access_key + '/' + credential_scope + ', ' +  'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature
				headers = {'x-amz-date':amzdate, 'Authorization':authorization_header}
				
				
				request_url = endpoint + '?' + canonical_querystring
				
				r = requests.get(request_url, headers=headers)
				#print(r.text)
				
				
				if (r.status_code != 200) and (r.status_code != 201):
					print("Attenzione errore nella richiesta ad AWS per la machineSN: {}".format(machineSN), flush = True)
					print('Response code: %d' % r.status_code, flush = True)
					print(r.text, flush = True)
					status = f'WARNING: alcuni passaggi non sono andati a buon fine, verificare nel file <{log_inserimenti_filename}> e <{current_time_str}.txt>'
					with open(resultTime_txt, 'a', newline='') as txtfile:
						txtfile.write("Attenzione errore nella chiamata ad AWS per la machineSN: {}".format(machineSN) + ', ' + r.text + '\n')
					with open(log_csv, 'a', newline='') as csvfile:
						csvwrite = csv.writer(csvfile)
						csvwrite.writerow(([current_time_str,timestamp,status]))
					with open(log_inserimenti, 'a', newline='') as csvfile:
						csvwrite = csv.writer(csvfile)
						csvwrite.writerow([current_time_str,timestamp,machineSN,str(r.status_code),"ERROR: errore nella chiamata ad AWS"])    
					sys.exit()
				else:
					#print("Richiesta ad AWS eseguita con successo per la machineSN: {}".format(machineSN), flush=True)
					#print('Response code: %d' % r.status_code, flush = True)
					with open(resultTime_txt, 'a', newline='') as txtfile:
						txtfile.write("Richiesta ad AWS eseguita con successo per la machineSN: {}".format(machineSN) + '\n')              
					#print(r.text, flush = True)
					
					
					
					fixed_part = {
					"POST to": "?$resultFormat=dataArray",
					"Headers": "Content-Type: application/json",
					"requests": []  
					}
					json_struct.append(fixed_part)
					
					#json_els = json.loads(r.text)
					#print(json_struct, flush = True)
					if r.text and 'dataArray' in r.text:
						try:
							json_els = r.json()
							execute_final_response = True
							el_by_id = {}  
							#print("Contenuto api : {}".format(json_els), flush=True)
							#print("l'api ha dati", flush=True)
							observations = {prop: 0 for prop in group_data['ID Locale Proprieta Osservata'].iloc[0]}                  
							observationsCount = ''
							for el in json_els:
								observed_properties_api = el.get("ID Locale Proprieta Osservata", "").split(",")
								#print(observed_properties_api, flush = True)
								#print(observedProperty, flush = True)
								for observedProperty, datastreamId in zip(group_data['ID Locale Proprieta Osservata'].iloc[0], group_data['ID Datastream Frost'].iloc[0]):           
									if (observedProperty in observed_properties_api) and (int_datastreamId == datastreamId):
										#print("Datastream", datastreamId, flush = True)
										#print(f"Confronto per l'observed property '{observedProperty}' e il datastream '{datastreamId}'", flush = True)
                                            
										filtered_data_array = []
										for data_array in el['dataArray']:
											phenomenon_time = data_array[0]
											phenomenon_time_IIpart = phenomenon_time.split('/')[-1]
                                                                                                                           
											phenomenon_time_IIpart_dt = datetime.strptime(phenomenon_time_IIpart, "%Y-%m-%dT%H:%M:%SZ")
											
											if interval_start < phenomenon_time_IIpart_dt <= interval_end:
												filtered_data_array.append(data_array)
										if filtered_data_array:
											for data_array in filtered_data_array:
												data_array[2] = current_time_str #stesso per ogni inserimento                                        

											if (int_datastreamId, phenomenon_time_IIpart_dt) not in added_datastream_ids:
    
												#print(f"Aggiungendo datastream ID {int_datastreamId} con tempo {phenomenon_time_IIpart_dt}", flush=True)
												
												num_elements =  len(filtered_data_array)
												expected_count = f"{observedProperty}={num_elements}/"
												el_by_id = {
														"id": f"batch_{interval_end_str}", #"batch_2024-04-30T13:00:00Z",
														"method": "post",
														"url": "CreateObservations",
														"body": [
															{
																"Datastream": {
																	"@iot.id": datastreamId
																},
																"components": [
																	"phenomenonTime",
																	"result",
																	"resultTime"
																],
																"dataArray": []
															}
														]
												}
												    #NAN
												#for item in filtered_data_array:
												#	print(item)
												data_array_nan = [None if isinstance(item, str) and item.lower() == "nan" else item for item in filtered_data_array]				
																					    			#print(el['dataArray'], flush = True)
												#print(data_array_nan, flush = True)
												
												el_by_id["body"][0]["dataArray"].extend(data_array_nan)
												#json_struct.append(el_by_id)
												fixed_part["requests"].append(el_by_id)
												#num_elements = len(el_by_id["body"][0]["dataArray"])
												observations[observedProperty] = num_elements
												added_datastream_ids.add((int_datastreamId, phenomenon_time_IIpart_dt))
												#print(added_datastream_ids)
												#print(num_elements, flush = True)
												#print(observations.items(), flush = True)
												#print(f"Aggiunto ds per op '{observedProperty}'")
												#print(f"Aggiunto ds per op dell'api '{observed_properties_api}'")
												#print("inizio", observationsCount,flush = True)
													

							#print(added_datastream_ids)				
							#print("Datastream", datastreamId, flush = True)				
							observationsCount = '/'.join([f"{prop}={count}" for prop, count in observations.items()]) + '/'                                   
							#print(json_struct, flush = True)
							#print("post loop", observationsCount,flush = True)
							if all(count == 0 for count in observations.values()):
								status = f'WARNING: alcuni passaggi non sono andati a buon fine, verificare nel file <{log_inserimenti_filename}> e <{current_time_str}.txt>'
								with open(log_inserimenti, 'a', newline='') as csvfile:
									csvwrite = csv.writer(csvfile)
									csvwrite.writerow([current_time_str, timestamp, machineSN, 'NO_CALL', observationsCount])
								with open(resultTime_txt, 'a', newline='') as txtfile:
									txtfile.write(f"Nessuna osservazione disponibile per {machineSN}/{observationsCount}\n")
								execute_final_response = False
							else:
								
								formatted_json = json.dumps(json_struct, indent=3, ensure_ascii=False)
								#print("qui al formatted", flush= True)
								#print(formatted_json)
								#print(json.dumps(json_struct, indent=3, ensure_ascii=False), flush=True)
								json.loads(formatted_json)
								json_file_form = "formatted_json.json"
								
								if any(count != 0 for count in observations.values()):
									obs_count.append([observationsCount])
                            	
								with open(json_file_form, 'w') as json_file:
									json_file.write(formatted_json)
									
								with open(json_file_form, 'r') as json_file:
									reader = json.load(json_file)
								
									#print(reader)
									for batch in reader:
										#print(batch)
										headers = {"Content-Type": "application/json"}
										data_for_machineSN = []
										esito = ''    
										requestBody = set()
										for request in batch['requests']:
                            	
											#data_array = request['body'][0]['dataArray']
											#num_elements = len(data_array)
											#print(f"Numero di elementi in dataArray per Datastream {request['body'][0]['Datastream']['@iot.id']}: {num_elements}")
                            	                	
											current_request_body = json.dumps(request['body'], sort_keys=True)
											request_url = str(base_url) + request['url'] + batch.get('POST to', '')
											final_api_url = str(base_url) + request['url']
											request_method = request['method'] 
											request_body = json.dumps(request['body'])										                            
											request_key = (request_method, request_url, request_body)
											if request_key not in requestBody:                          
												data_for_machineSN.append(request_key)
												#print(f"Numero di elementi in dataArray per Datastream {request['body'][0]['Datastream']['@iot.id']}: {num_elements}")
											requestBody.add(request_key)
										#print("oc", observationsCount,flush = True)                                        
											#print(data_for_machineSN, flush = True)                                        
                            	
								#print(temp_data, flush = True)
						    	                       
								#print(data_for_machineSN, flush = True)
                            	
								#print(is_last_datastream, flush = True)
								temp_data.extend(data_for_machineSN)
								status = 'OK'
								with open(log_inserimenti, 'a', newline='') as csvfile:
									csvwrite = csv.writer(csvfile)	 
									csvwrite.writerow([current_time_str,timestamp,machineSN,'201',observationsCount])
                            	
								os.remove(json_file_form)
								del json_els, el_by_id, data_array_nan, fixed_part 
								data_for_machineSN.clear()
								#print("oc1", observationsCount,flush = True)     	
                            	
						except json.JSONDecodeError as e:
							esito = "ERROR: errore durante il parsing della risposta JSON dell'api AWS\n"
							respcode = 'HTTP error response AWS'
							print(f"Errore durante il parsing della risposta JSON dell'api AWS:", e, flush = True)
							with open(resultTime_txt, 'a', newline='') as txtfile:
								txtfile.write(esito)
							with open(log_inserimenti, 'a', newline='') as csvfile:
								csvwrite = csv.writer(csvfile)	 
								csvwrite.writerow([current_time_str,timestamp,machineSN,respcode,esito])
							
					else:
						esito = f"La risposta da AWS è vuota per '{machineSN}'.\n"
						status = 'ERROR: errore nella chiamata ad AWS per qualche intervallo e centralina' 
						print(f"La risposta da AWS è vuota per '{machineSN}'.\n", flush = True)
						with open(resultTime_txt, 'a', newline='') as txtfile:
							txtfile.write(esito)
            	
								
		unique_requests = {}
		
		for request_method, request_url, request_body in temp_data:
			
			request_key = (request_method, request_url, request_body)
			
			if request_key not in unique_requests:
				
				unique_requests[request_key] = (request_method, request_url, request_body)
		
		
		temp_data_unique = list(unique_requests.values())
		

            
		for request_method, request_url, request_body in temp_data_unique:
			response = requests.request(request_method, request_url, data=request_body, headers=headers, auth=(access_API_key, secret_API_key))
			
			if (response.status_code != 200) and (response.status_code != 201):							
				status = f'WARNING: alcuni passaggi non sono andati a buon fine, verificare nel file <{log_inserimenti_filename}> e <{current_time_str}.txt>'                            
			
				with open(resultTime_txt, 'a', newline='') as txtfile:
					txtfile.write(f"Attenzione errore nell'inserimento con API FROST per '{machineSN}'\n")
			 
			else:
				print(f"Inserimento con API FROST eseguito con successo per '{machineSN}'", flush=True)
				#print("Response code:", response.status_code, "\n", flush = True)
				#print("Response body:", response.text)
				esito = str(response.status_code)   
				with open(resultTime_txt, 'a', newline='') as txtfile:
					txtfile.write(f"Inserimento con API FROST eseguito con successo per '{machineSN}'\n") 	            
		temp_data = []
		json_struct = []
		added_datastream_ids.clear()
		       
	print(f"Esecuzione script terminata", flush = True)
	
	with open(log_csv, 'a', newline='') as csvfile:
    #ResultTime[*],PhenomenonTime,Status
		csvwrite = csv.writer(csvfile)
		csvwrite.writerow(([current_time_str,timestamp,status]))
 
 #Il file con i printout di dettaglio viene eliminato a fine esecuzione script SOLO se non ci sono stati errori.
	with open(log_csv, newline='') as csvfile:
		reader = csv.DictReader(csvfile)
		for row in reader:
        #status è "OK"
			if row['Status'] == 'OK' and row['ResultTime'] == current_time_str:
            #elimino il txt
				if os.path.exists(resultTime_txt):
					os.remove(resultTime_txt)
        
				
except (HTTPError,requests.exceptions.RequestException) as e: 
	status = f'ERROR: Esecuzione script non iniziata.\n'
	esito = 'Errore durante la lettura dei configuration parameters\n'
	with open(resultTime_txt, 'a', newline='') as txtfile:
		txtfile.write(esito)
	with open(log_csv, 'a', newline='') as csvfile:
		csvwrite = csv.writer(csvfile)
		csvwrite.writerow(([current_time_str,timestamp,status]))	 
	print(e, flush=True)