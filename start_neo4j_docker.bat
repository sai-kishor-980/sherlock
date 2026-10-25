@echo off
echo ========================================================
echo Starting Neo4j 5 Community Container for Sherlock AI
echo ========================================================
echo Web UI: http://localhost:7474
echo Bolt Protocol: bolt://localhost:7687
echo Username: neo4j
echo Password: sherlock2026
echo ========================================================

docker run -d ^
  --name sherlock-neo4j ^
  -p 7474:7474 -p 7687:7687 ^
  -e NEO4J_AUTH=neo4j/sherlock2026 ^
  -e NEO4J_PLUGINS="[\"apoc\"]" ^
  -v neo4j_data:/data ^
  neo4j:5-community

if %ERRORLEVEL% EQU 0 (
    echo.
    echo [SUCCESS] Neo4j container started! Open http://localhost:7474 in your browser.
) else (
    echo.
    echo [INFO] Container might already exist. Attempting to start existing container...
    docker start sherlock-neo4j
)
pause
