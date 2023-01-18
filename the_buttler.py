#!/bin/env python3

import os
import nmap
import re
import json
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from keras.models import Sequential
from keras.layers import Dense

# Escaneamento do host com o nmap
scanner = nmap.PortScanner()
scanner.scan('host', '-sV')

# Armazenamento dos resultados do escaneamento
scan_results = {}
for host in scanner.all_hosts():
    scan_results[host] = {}
    for protocol in scanner[host].all_protocols():
        scan_results[host][protocol] = {}
        lport = scanner[host][protocol].keys()
        for port in lport:
            scan_results[host][protocol][port] = {}
            scan_results[host][protocol][port]['name'] = scanner[host][protocol][port]['name']
            scan_results[host][protocol][port]['product'] = scanner[host][protocol][port]['product']

# Armazenamento dos resultados do escaneamento em um arquivo JSON
with open('scan_results.json', 'w') as f:
    json.dump(scan_results, f)

# Leitura dos arquivos de exploit-db fornecidos pelo sistema operacional
exploit_db_files = []
for root, dirs, files in os.walk('/usr/share/exploitdb/'):
    for file in files:
        if file.endswith('.txt'):
            exploit_db_files.append(os.path.join(root, file))

# Criação de um conjunto de dados com os resultados do escaneamento e as informações de exploit-db
data = []
for file in exploit_db_files:
    with open(file, 'r') as f:
        lines = f.readlines()
        for line in lines:
            if 'Exploit Title:' in line:
                exploit_title = line.split(':')[1].strip()
            if 'Software:' in line:
                software = line.split(':')[1].strip()
            if 'Port:' in line:
                port = line.split(':')[1].strip()
            if 'Vulnerability Type:' in line:
                vulnerability_type = line.split(':')[1].strip()
    for host in scan_results.keys():
        for protocol in scan_results[host].keys():
            if port in scan_results[host][protocol].keys():
                if software in scan_results[host][protocol][port]['product']:
                    data.append([host, protocol, port, scan_results[host][protocol][port]['product'], vulnerability_type])

# Divisão dos dados em conjuntos de treinamento e teste
X = np.array([i[3] for i in data])
y = np.array([i[4] for i in data])
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
# Codificação das variáveis de saída

encoder = LabelEncoder()
y_train = encoder.fit_transform(y_train)
y_test = encoder.transform(y_test)
# Criação do modelo de deep learning

model = Sequential()
model.add(Dense(64, input_dim=X_train.shape[1], activation='relu'))
model.add(Dense(32, activation='relu'))
model.add(Dense(16, activation='relu'))
model.add(Dense(y_train.shape[1], activation='softmax'))
model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])
# Treinamento do modelo

model.fit(X_train, y_train, epochs=50, batch_size=32)
Avaliação do modelo com os dados de teste

score = model.evaluate(X_test, y_test, batch_size=32)
print("\nPerda do modelo: ", score[0])
print("Precisão do modelo: ", score[1])
# Uso do modelo para previsões

y_pred = model.predict(X_test)
print("Previsões: ", encoder.inverse_transform(y_pred))


# Esse código utiliza o módulo python nmap para escanear um host específico e armazena os resultados do escaneamento em um arquivo JSON. Ele também lê os arquivos de exploit-db fornecidos pelo sistema operacional e cria um conjunto de dados com os resultados do escaneamento e as informações de exploit-db. Ele então divide os dados em conjuntos de treinamento e teste e cria um modelo de deep learning usando o keras para classificar as vulnerabilidades com base nas informações do produto. O modelo é treinado e avaliado com os dados de teste e as previsões são impressas.
# Esse código é uma amostra, você deve ajustá-lo de acordo com sua necessidade e disponibilidade dos dados.
