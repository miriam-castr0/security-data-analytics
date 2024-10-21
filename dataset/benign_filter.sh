#!/bin/bash

# Pasta contendo os arquivos PCAP originais
pasta_origem="/mnt/c/Users/mpires/OneDrive - Universidade do Minho/Ambiente de Trabalho/lucid/pcap_final"

# Pasta onde os arquivos PCAP filtrados serão salvos
pasta_destino="/mnt/c/Users/mpires/OneDrive - Universidade do Minho/Ambiente de Trabalho/dataset/benign"

# Filtro a ser aplicado
filtro='not ((ip.src == 192.168.50.1 and ip.dst == 172.16.0.5) or (ip.src == 192.168.50.4 and ip.dst == 172.16.0.5) or (ip.src == 172.16.0.5 and ip.dst == 192.168.50.1) or (ip.src == 172.16.0.5 and ip.dst == 192.168.50.4))'

# Contador de arquivos processados
arquivos_processados=0

# Total de arquivos a processar
total_arquivos=$(find "$pasta_origem" -type f | wc -l)

# Iterar sobre todos os arquivos PCAP na pasta de origem
find "$pasta_origem" -type f | while read -r arquivo; do
    nome_arquivo=$(basename "$arquivo")
    # Aplicar o filtro e salvar em um novo arquivo na pasta de destino
    tshark -r "$arquivo" -Y "$filtro" -w "$pasta_destino/benign_$nome_arquivo"
    arquivos_processados=$((arquivos_processados+1))
    echo "Progresso: $arquivos_processados / $total_arquivos arquivos processados."
done

echo "Processamento concluído. Todos os arquivos foram processados."