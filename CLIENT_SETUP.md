# Client Setup

Este servidor esta configurado para aceitar um cliente Ragnarok compativel com:

- `PACKETVER 20211103`
- `login_port 6900`
- `char_ip 209.50.241.180`
- `char_port 6121`
- `map_ip 209.50.241.180`
- `map_port 5121`

As referencias estao em:

- `src/config/packets.hpp`
- `conf/login_athena.conf`
- `conf/char_athena.conf`
- `conf/map_athena.conf`

## Cliente recomendado

Use um executavel da mesma linha do packetver:

- `2021-11-03aRagexeRE`

Evite misturar um cliente de outra data. Em `rAthena`, diferenca de packetver normalmente causa falha no login, desconexao ao selecionar personagem ou erro ao entrar no mapa.

## Ajustes minimos no cliente

O cliente precisa ter um `clientinfo.xml` apontando para o login server:

```xml
<?xml version="1.0" encoding="euc-kr" ?>
<clientinfo>
    <desc>rAthena</desc>
    <servicetype>korea</servicetype>
    <servertype>sakray</servertype>
    <connection>
        <display>rAthena</display>
        <desc>rAthena</desc>
        <address>209.50.241.180</address>
        <port>6900</port>
        <version>55</version>
        <langtype>1</langtype>
        <registrationweb>https://127.0.0.1/</registrationweb>
        <aid>
            <admin>2000000</admin>
        </aid>
    </connection>
</clientinfo>
```

O arquivo normalmente fica em um destes caminhos, dependendo do cliente:

- `data/clientinfo.xml`
- `System/clientinfo.xml`

## Patches esperados

Os patches usuais para esse cenario sao:

- `Read Data Folder First`
- `Skip Service Select`
- `Use Custom Aura Sprites` se voce usar auras customizadas
- `Disable Ragexe Filename Check` se o cliente exigir nome especifico
- `Remove Login Delay` opcional

Nao use patch para desativar criptografia de pacote se o executavel da mesma data ja estiver alinhado com o `PACKETVER`.

## Observacoes importantes

- O servidor esta com `use_MD5_passwords: no`, entao a conta deve usar senha normal do `rAthena`.
- O servidor esta com `pincode_enabled: yes`, entao o cliente precisa suportar pincode. O packetver atual suporta.
- O servidor esta com `use_web_auth_token: yes`, o que e esperado para clientes modernos nessa faixa.
- Se voce for testar localmente na mesma maquina, troque o IP do `clientinfo.xml` para `127.0.0.1` ou para o IP LAN correto.
- Se o cliente abrir e fechar ou travar antes do login, o problema normalmente e executavel/data incompatibil ou falta de patch basico.

## Checklist rapido

1. Obter um cliente `2021-11-03aRagexeRE`.
2. Aplicar os patches basicos.
3. Configurar `clientinfo.xml` com `209.50.241.180:6900`.
4. Garantir que as portas `6900`, `6121` e `5121` estao acessiveis.
5. Logar com uma conta existente no banco do servidor.

## Se quiser fechar a integracao completa

O proximo passo natural e preparar um pacote de cliente com:

- executavel correto
- `clientinfo.xml`
- `data.grf` ou `System/` compativel
- atalhos de inicializacao
- opcionalmente `itemInfo.lua` e traducao

Se voce quiser, no proximo passo eu monto contigo o pacote final do cliente e te digo exatamente quais arquivos colocar em cada pasta.
