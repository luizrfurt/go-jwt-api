@echo off
setlocal enabledelayedexpansion

:: Configurações
set "DIRETORIO_ORIGEM=C:\go-projects\go-jwt-api"
set "ARQUIVO_SAIDA=ai-learn.txt"

:: Verifica se o diretório existe
if not exist "%DIRETORIO_ORIGEM%" (
    echo ERRO: Diretório não encontrado: %DIRETORIO_ORIGEM%
    pause
    exit /b 1
)

:: Remove arquivo de saída anterior se existir
if exist "%ARQUIVO_SAIDA%" del "%ARQUIVO_SAIDA%"

echo Iniciando extração de arquivos .go...
echo Diretório origem: %DIRETORIO_ORIGEM%
echo Arquivo de saída: %ARQUIVO_SAIDA%
echo.

set contador=0

:: Percorre recursivamente todas as pastas e subpastas
for /r "%DIRETORIO_ORIGEM%" %%f in (*.go) do (
    set /a contador+=1
    
    echo Processando: %%f
    
    :: Adiciona separador e informações do arquivo
    echo. >> "%ARQUIVO_SAIDA%"
    echo ============================================= >> "%ARQUIVO_SAIDA%"
    echo ARQUIVO: %%f >> "%ARQUIVO_SAIDA%"
    echo ============================================= >> "%ARQUIVO_SAIDA%"
    echo. >> "%ARQUIVO_SAIDA%"
    
    :: Adiciona o conteúdo do arquivo
    type "%%f" >> "%ARQUIVO_SAIDA%" 2>nul
    
    :: Adiciona separador final
    echo. >> "%ARQUIVO_SAIDA%"
    echo. >> "%ARQUIVO_SAIDA%"
)

echo.
echo Extração concluída!
echo Total de arquivos .go processados: !contador!
echo Arquivo gerado: %ARQUIVO_SAIDA%
echo.

if !contador! equ 0 (
    echo AVISO: Nenhum arquivo .go foi encontrado no diretório especificado.
)