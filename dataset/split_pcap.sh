#!/bin/bash

# Pasta contendo os arquivos PCAP originais
pasta_origem="/mnt/c/Users/mpires/OneDrive - Universidade do Minho/Ambiente de Trabalho/dissertation/multiclassifier/dataset/NetBios"

# Função para dividir os arquivos PCAP
split_pcap() {
    local arquivo="$1"
    local pasta_destino="$2"
    local nome_arquivo=$(basename "$arquivo")
    local base_nome="${nome_arquivo%.*}"

    # Usando tshark para contar o número de pacotes
    total_packets=$(tshark -r "$arquivo" -T fields -e frame.number | tail -n 1)

    # Usando editcap para dividir o arquivo em duas partes
    editcap -c $(($total_packets / 2)) "$arquivo" "$pasta_destino/${base_nome}_part.pcap"

    # Renomeando as partes geradas
     # Renomeando a primeira parte gerada
    find "${pasta_destino}" -type f -name "${base_nome}_part_00000_*.pcap" -exec mv {} "${pasta_destino}/${base_nome}_1.pcap" \;

    # Renomeando a segunda parte gerada
    find "${pasta_destino}" -type f -name "${base_nome}_part_00001_*.pcap" -exec mv {} "${pasta_destino}/${base_nome}_2.pcap" \;

    find "${pasta_destino}" -type f -name "${base_nome}_part_00002_*.pcap" -exec mv {} "${pasta_destino}/${base_nome}_3.pcap" \;
}

# Contador de arquivos processados
arquivos_processados=0

# Total de arquivos a processar
total_arquivos=$(find "$pasta_origem" -type f -name "*.pcap" | wc -l)

# Iterar sobre todos os arquivos PCAP na pasta de origem
find "$pasta_origem" -type f -name "*.pcap" | while read -r arquivo; do
    tamanho=$(stat -c %s "$arquivo")
    if [ "$tamanho" -gt $((100 * 1024 * 1024)) ]; then
        split_pcap "$arquivo" "$(dirname "$arquivo")"
    fi
    arquivos_processados=$((arquivos_processados + 1))
    echo "Progresso: $arquivos_processados / $total_arquivos arquivos processados."
done

echo "Processamento concluído. Todos os arquivos foram processados."
