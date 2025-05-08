import sys, os 
from parameters import read_param
import base64, datetime, hashlib, hmac 
import requests 
import csv
import calendar
import json
from requests.exceptions import HTTPError
import pandas as pd
import time
import math
import requests
from datetime import timedelta
try:
    #Reading  arguments
	print ('Number of arguments:', len(sys.argv), 'arguments.', flush = True)
	print ('Argument List:', str(sys.argv), flush = True)
    
	machineSN = str(sys.argv[1])
	start_date_str = str(sys.argv[2])
	end_date_str = str(sys.argv[3])
	days_str = sys.argv[4]
	days = int(days_str)
	timestamp = ''
    #Reading configuration parameters
	print('Lettura dei configuration parameters...\n', flush = True)
	aws_params = read_param('data1/parameters.ini', 'aws_credentials')
	frost = read_param('data1/parameters.ini', 'frost')
	files = read_param('data1/parameters.ini', 'files')
	status = 'OK'
	log_csv  = files.get('log_path') + files.get('log_filename')
	log_csv_path = files.get('log_path')
	
	log_filename = files.get('log_filename')
	log_inserimenti_filename = files.get('log_frost_filename')

	datastream_csv_path = files.get('mapping_path') + files.get('mapping_filename')
	datastream_filename = files.get('mapping_filename')

	resultTime_path = files.get('mapping_path') 
    
	access_key  = aws_params.get('aws_access_key_id')
	secret_key = aws_params.get('aws_secret_access_key')
	access_API_key  = frost.get('username')
	secret_API_key = frost.get('password')
	base_url = frost.get('server_url')
#--------------------------------------------------------------------------------   
#Fare in modo che il log venga creato al primo utilizzo

	current_time = datetime.datetime.utcnow()
	current_time_str = current_time.strftime('%Y-%m-%dT%H:%M:%SZ') 
	resultTime_txt = os.path.join(resultTime_path, '{}.txt'.format(current_time_str))
	
	# Crea le directory nel percorso se non esistono
	os.makedirs(resultTime_path, exist_ok=True)
	
	# Crea e scrivi nel file
	with open(resultTime_txt, 'w', newline='') as txtfile:
		print(f"Il file txt '{current_time_str}' è stato creato.\n", flush=True)
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
	else:
			with open(resultTime_txt, 'a', newline='') as txtfile:
				txtfile.write(f"Il file CSV '{datastream_filename}' è stato trovato.\n")
			print(f"Il file di mapping '{datastream_filename}' esiste già al percorso '{datastream_csv_path}'." + "\n", flush = True)

	#Converte due stringhe (start_date_str e end_date_str) nel formato dd/mm/yyyy in oggetti datetime         

	start_date = datetime.datetime.strptime(start_date_str, '%d/%m/%Y')
	end_date = datetime.datetime.strptime(end_date_str, '%d/%m/%Y')

	start_date = start_date.replace(hour=0, minute=0, second=0, microsecond=0)
	end_date = end_date.replace(hour=23, minute=59, second=59, microsecond=999999)
	date_ranges = []

	current_date = start_date
 
	while current_date < end_date:
		# Aggiungi l'intervallo di 2 giorni
		next_date = current_date + datetime.timedelta(days=days)
		
		# Se l'ultimo intervallo supera end_date, imposrato come end_date
		if next_date > end_date:
			next_date = end_date		
		date_ranges.append((current_date, next_date))
		
		current_date = next_date + datetime.timedelta(seconds=1)
		
#Modifica dell'ultimo intervallo per terminare all'inizio del mese successivo


	if date_ranges:
		last_start, last_end = date_ranges[-1]	
		if end_date.month == 1:
			last_end = datetime.datetime(year=end_date.year, month=2, day=1)
		elif end_date.month == 2:
			last_end = datetime.datetime(year=end_date.year, month=3, day=1)
		elif end_date.month == 3:
			last_end = datetime.datetime(year=end_date.year, month=4, day=1)
		elif end_date.month == 4:
			last_end = datetime.datetime(year=end_date.year, month=5, day=1)
		elif end_date.month == 5:
			last_end = datetime.datetime(year=end_date.year, month=6, day=1)
		elif end_date.month == 6:
			last_end = datetime.datetime(year=end_date.year, month=7, day=1)
		elif end_date.month == 7:
			last_end = datetime.datetime(year=end_date.year, month=8, day=1)
		elif end_date.month == 8:
			last_end = datetime.datetime(year=end_date.year, month=9, day=1)
		elif end_date.month == 9:
			last_end = datetime.datetime(year=end_date.year, month=10, day=1)
		elif end_date.month == 10:
			last_end = datetime.datetime(year=end_date.year, month=11, day=1)
		elif end_date.month == 11:
			last_end = datetime.datetime(year=end_date.year, month=12, day=1)
		elif end_date.month == 12:
			last_end = datetime.datetime(year=end_date.year + 1, month=1, day=1)
		date_ranges[-1] = (last_start, last_end)

 
	all_data_machineSN = []
	status = 'OK'		

	#Request API
	method = 'GET'
	service = 'execute-api'
	host = '2fgy9ddyeg.execute-api.eu-west-1.amazonaws.com'
	region = 'eu-west-1'
	endpoint = 'https://2fgy9ddyeg.execute-api.eu-west-1.amazonaws.com/Ediaqi/data'
    
	fixed_part = {
				"POST to": "?$resultFormat=dataArray",
				"Headers": "Content-Type: application/json",
				"requests": []  
				}	
	
	def sign(key, msg):
	    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()
	
	def getSignatureKey(key, dateStamp, regionName, serviceName):
		kDate = sign(('AWS4' + key).encode('utf-8'), dateStamp)
		kRegion = sign(kDate, regionName)
		kService = sign(kRegion, serviceName)
		kSigning = sign(kService, 'aws4_request')
		return kSigning

	df = pd.read_csv(datastream_csv_path)
	machineSN_observedProps = df.groupby('ID Locale Sensore').agg(lambda x: x.tolist())
	
	unique_request_bodies = set()
	observations = {}              
	observationsCount = ''
	observation_logs = []
	json_file_form = "formatted_json.json"
	datastreams_data = {}
	json_struct = []
	added_datastream_ids = set()
	temp_data = []
	obs_count = []
	all_json_els = []
	
	for machineSNF, group_data in machineSN_observedProps.iterrows():
		time_ranges = []
		if machineSN == machineSNF:
			for index, (date_a, date_b) in enumerate(date_ranges):
				t = datetime.datetime.utcnow()
				amzdate = t.strftime('%Y%m%dT%H%M%SZ')
				datestamp = t.strftime('%Y%m%d') # Date w/o time, used in credential scope
				canonical_uri = '/Ediaqi/data'
				current_time = datetime.datetime.utcnow()
				current_time_str = current_time.strftime('%Y-%m-%dT%H:%M:%SZ')
				timestamp_a = calendar.timegm(date_a.utctimetuple())
				timestamp_b = calendar.timegm(date_b.utctimetuple())                

				time_rangeA_str = date_a.strftime('%Y-%m-%dT%H:%M:%SZ')
				time_rangeB_str = date_b.strftime('%Y-%m-%dT%H:%M:%SZ')
				timestamp = time_rangeA_str + '/' + time_rangeB_str
				time_ranges.append((timestamp, timestamp_a, timestamp_b))

				group_data = machineSN_observedProps.loc[machineSN]
				observedProperty = group_data['ID Locale Proprieta Osservata']

			
            
				#----------------------------------------------------------------------	
			
				request_parameters = f"machineSN={machineSN}&tsFrom={timestamp_a}&tsTo={timestamp_b}"
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
				
				r = requests.get(request_url, headers=headers)#, timeout=10)
				
				
				if (r.status_code != 200) and (r.status_code != 201):
					print("Attenzione errore nella richiesta ad AWS per la machineSN: {}".format(machineSN), flush = True)
					
					status = f'WARNING: alcuni passaggi non sono andati a buon fine, verificare nel file <{log_inserimenti_filename}> e <{current_time_str}.txt>'
					with open(resultTime_txt, 'a', newline='') as txtfile:
						txtfile.write("Attenzione errore nella chiamata ad AWS per la machineSN: {}".format(machineSN) + ', ' + r.text + '\n')
					with open(log_csv, 'a', newline='') as csvfile:
						csvwrite = csv.writer(csvfile)
						csvwrite.writerow(([current_time_str,timestamp,status]))
					with open(log_inserimenti, 'a', newline='') as csvfile:
						csvwrite = csv.writer(csvfile)
						csvwrite.writerow([current_time_str,timestamp,machineSN,str(r.status_code),"ERROR: errore nella chiamata ad AWS"])    
			
				else:
					
					with open(resultTime_txt, 'a', newline='') as txtfile:
						txtfile.write("Richiesta ad AWS eseguita con successo per la machineSN: {}".format(machineSN) + '\n')              
		
					
					json_struct.append(fixed_part)
					
					json_els = json.loads(r.text)
					
					if r.text:
				    
						try:
							json_els = r.json()
							
							all_json_els.append(json_els)
							execute_final_response = True
							el_by_id = {}  
							observations = {prop: 0 for prop in group_data['ID Locale Proprieta Osservata']}              
							observationsCount = ''
							
							for el in json_els:
								observed_properties_api = el.get("ID Locale Proprieta Osservata", "").split(",")

								for observedProperty, datastreamId in zip(group_data['ID Locale Proprieta Osservata'], group_data['ID Datastream Frost']):
									
									if observedProperty in observed_properties_api:
										if datastreamId not in datastreams_data:
											datastreams_data[datastreamId] = []
										for data_array in el['dataArray']:
											
											data_array[2] = current_time_str #stesso per ogni inserimento
												
										num_elements =  len(el.get('dataArray', []))

										el_by_id = {
													"id": "batch_{}".format(current_time_str), #"batch_2024-04-30T13:00:00Z",
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
															"dataArray":[]
														}
													]
											}
									    	    #NAN
								                                              
										data_array_nan= el.get('dataArray', [])
										

										el_by_id["body"][0]["dataArray"].extend(data_array_nan)
										
										fixed_part["requests"].append(el_by_id)
										observations[observedProperty] = num_elements

										               
							observationsCount = '/'.join([f"{prop}={count}" for prop, count in observations.items()]) + '/'  
							observation_logs.append((current_time_str, timestamp, machineSN, observationsCount))
							


							if all(count == 0 for count in observations.values()):
								status = f'WARNING: alcuni passaggi non sono andati a buon fine, verificare nel file <{log_inserimenti_filename}> e <{current_time_str}.txt>'
								with open(log_inserimenti, 'a', newline='') as csvfile:
									csvwrite = csv.writer(csvfile)
									csvwrite.writerow([current_time_str, timestamp, machineSN, 'NO_CALL', observationsCount])
								with open(resultTime_txt, 'a', newline='') as txtfile:
									txtfile.write(f"Nessuna osservazione disponibile per {machineSN}/{observationsCount}\n")
								execute_final_response = False
							else:
			                                    
								formatted_json = json.dumps(json_struct, indent=3, ensure_ascii=False, allow_nan=True)

                                
								with open(json_file_form, 'w') as json_file:
									json_file.write(formatted_json)       
								with open(json_file_form, 'r') as json_file:

									reader = json.load(json_file)
									unique_request_bodies = set() 
									data_for_machineSN = []                            
									for batch in reader:
										headers = {"Content-Type": "application/json"}
										data_for_machineSN = []
										esito = ''    
										requestBody = set()
										for request in batch['requests']:
                            	
                            	                	
											current_request_body = json.dumps(request['body'], sort_keys=True)
											request_url = str(base_url) + request['url'] + batch.get('POST to', '')
											final_api_url = str(base_url) + request['url']
											request_method = request['method'] 
											request_body = json.dumps(request['body'])										                            
											request_key = (request_method, request_url, request_body)
											if request_key not in requestBody:                          
												data_for_machineSN.append(request_key)
                                                
											requestBody.add(request_key)
											

								temp_data.extend(data_for_machineSN)
								status = 'OK'
								with open(log_inserimenti, 'a', newline='') as csvfile:
									csvwrite = csv.writer(csvfile)	 
									csvwrite.writerow([current_time_str,timestamp,machineSN,'201',observationsCount])
                            	
								os.remove(json_file_form)
								del json_els, el_by_id, data_array_nan
								data_for_machineSN.clear()
                            	
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


 #Pulisce i dati, rimuovendo i valori NaN (Not a Number) e sostituendoli con None a seconda di cosa riceverà in input
	def clean_data(data):
		if isinstance(data, dict):
			return {k: clean_data(v) for k, v in data.items()}
		elif isinstance(data, list):
			return [clean_data(item) for item in data]
		elif isinstance(data, float) and (data != data): 
			return None  
		return data
# Verifica la presenza di valori NaN nei dati e solleva un'eccezione se ne trova        
	def validate_data(data):
		if isinstance(data, dict):
			for k, v in data.items():
				if v != v:  
					raise ValueError(f"Invalid data found: {k} is NaN")
				validate_data(v)
		elif isinstance(data, list):
			for item in data:
				validate_data(item)

# Suddivide una lista (data) in blocchi (batch_size) e li restituisce uno alla volta usando yield (un generatore).

#Usa un ciclo for con range(0, len(data), batch_size), che avanza di batch_size alla volta.
#Ad ogni iterazione, restituisce una sotto-lista di data[i:i + batch_size].
#yield fa sì che la funzione non restituisca tutti i dati subito, ma generi i blocchi uno per volta, risparmiando memoria.    

	def process_data_in_batches(data, batch_size):
		for i in range(0, len(data), batch_size):
			yield data[i:i + batch_size]
            
	batch_size = 1000  #matop
	query_timeout = 30 	
	processed_count = 0

#Processo dati in batch e li invia a un'API, gestendo errori e timeout.
# Gestisce errori e timeout (ritenta in caso di timeout)
# Registra gli errori nei file di log (error_logs.txt, response_logs.txt)
# Evita di processare richieste troppo grandi
	failed_requests = []  # Lista per memorizzare le richieste fallite
	for batch in process_data_in_batches(temp_data_unique, batch_size): #itera su ogni batch per processarlo uno alla volta.
	
		for request_method, request_url, request_body in batch:
        # Pulisce le richieste
			request_body = clean_data(request_body)
			
			try:
                #Vede se qualche dato non è valido
				validate_data(request_body)
			except ValueError as e:
				print(f"Data validation error: {e}")
				with open('error_logs.txt', 'a') as error_file:
					error_file.write(f"Data validation error: {e}\n")
				continue
			
			
			response = None
            #nvia la richiesta HTTP all'API (requests.request(...)).
#Usa autenticazione (auth=(access_API_key, secret_API_key)).
#Imposta un timeout (query_timeout = 30 sec).
#Se la richiesta va a buon fine, incrementa processed_count.
			try:
				response = requests.request(
					request_method, request_url, data=request_body,
					headers=headers, auth=(access_API_key, secret_API_key),
					timeout=query_timeout
				)
				response.raise_for_status()
				processed_count += 1
			except requests.exceptions.Timeout:
            #Se la richiesta scade per timeout, aspetta 1 secondo e la ritenta. Se fallisce ancora, registra l'errore.
				print("Query timed out. Retrying...")
				time.sleep(1)
				try:
					response = requests.request(
						request_method, request_url, data=request_body,
						headers=headers, auth=(access_API_key, secret_API_key),
						timeout=query_timeout
					)
					response.raise_for_status()
					processed_count += 1
				except requests.exceptions.RequestException as e:
					print(f"Request failed after retry: {e}")
					failed_requests.append({
						'method': request_method,
						'url': request_url,
						'body': request_body,
						'error': str(e),
						'response_status': response.status_code if response else 'unknown',
						'response_text': response.text if response else 'No response'
					})
			except requests.exceptions.RequestException as e:
				print(f"Request failed: {e}")
				failed_requests.append({
					'method': request_method,
					'url': request_url,
					'body': request_body,
					'error': str(e),
					'response_status': response.status_code if response else 'unknown',
					'response_text': response.text if response else 'No response'
				})
			
			if response and response.status_code not in [200, 201]:
				with open(resultTime_txt, 'a', newline='') as txtfile:
					txtfile.write(f"Attenzione errore nell'inserimento con API FROST per '{machineSN}'\n")
				
				with open('response_logs.txt', 'a', newline='') as response_log_file:
					response_log_file.write(f"WARNING: Request to {request_url} returned status code {response.status_code}\n")
					response_log_file.write(f"Response body: {response.text}\n\n")
		

			
	print(f"Processed {processed_count} out of {len(temp_data_unique)} items.")          
	temp_data = []
	json_struct = []
	added_datastream_ids.clear()

                        
	print(f"Esecuzione script terminata", flush = True)

	
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