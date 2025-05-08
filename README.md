# 7_LAS_FROST_DynamicData
Script that dynamically ingests data to LAS FROST Server  

### Script caricamento dati dinamici

Lo script si occupa del caricamento dei dati dinamici sul server FROST di Lab Service.
La chiamata viene eseguita indicando il parametro (in giorni) che definisce la massima ampiezza temporate su cui interrogare l’API AWS:

```python frost_data_sync_2.2.py 5```

Lo script si appoggia su di un file parameters, di configurazione, contenuto all'interno della cartella Data, che ha la seguente struttura:
```
[aws_credentials]
aws_access_key_id = <da compilare>
aws_secret_access_key = <da compilare>
[frost]
username = <da compilare>
password = <da compilare>
server_url = https://frost.labservice.it/FROST-Server/v1.1/
[files]
log_path = ./data/
log_filename = log.csv
log_frost_filename = log_inserimenti.csv
mapping_path = ./data/
mapping_filename = datastreams.csv
```
Il file “datastreams.csv” è un file di input che serve per mappare gli ID “locali” di LAS di sensori e parametri negli ID dei datastreams usati nel server FROST.

I file “log.csv” e “log_inserimenti.csv” vengono generati dallo script al momento della prima esecuzione e servono per seguire l’esito delle operazioni.
Si riempiono in append e mantengono quindi traccia di ciascuna delle esecuzioni passate. 


### Script check dati centraline dall'API AWS

#### Esempio di utilizzo

Lo script recupera le risposte dell'API AWS per la centralina specificata e l'intervallo di tempo desiderato (in formato UNIX).  

Lo script viene lanciato senza specificare parametri:

```python amazon_ed.py```

Prima di eseguire lo script, è necessario modificare la variabile request_parameters all'interno dello script con i valori desiderati.
#### Esempio di `request_parameters`:

request_parameters = 'machineSN=LS0623020166&tsFrom=1728517200&tsTo=1728608100'

### Script recupero del pregresso

Lo script permette di recuperare le osservazioni pregresse per un intervallo di giorni specificato, interrogando l’API AWS.  
Si basa sugli stessi file di configurazione `parameters` e `datastreams.csv` utilizzati da `frost_data_sync_2.2.py`.  

Per lanciare il recupero delle osservazioni, si può utilizzare il comando:

```sh batch_insert ```

Il file batch_insert ha la seguente struttura:

```
echo -n INIZIO BATCH
python frost_sync_pregresso_v1.2.py LS0623020122 1/08/2023 31/08/2023 2
python frost_sync_pregresso_v1.2.py LS0623020122 1/09/2023 30/09/2023 2
python frost_sync_pregresso_v1.2.py LS0623020122 1/10/2023 31/10/2023 2
echo FINE BATCH.
```
Per ogni esecuzione dello script, è necessario specificare:

- La centralina per cui si desidera recuperare le osservazioni;
- L’intervallo di tempo per cui si vogliono ottenere i dati;
- Il parametro "giorni", che definisce l’ampiezza temporale della richiesta.

Le osservazioni recuperate verranno direttamente caricate su FROST di Lab Service.
