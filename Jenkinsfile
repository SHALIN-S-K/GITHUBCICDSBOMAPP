pipeline {
    agent any
    
    environment {
        TARGET_PATH = "."
        OUTPUT_FOLDER = "${env.JOB_NAME.split('/')[0]}"
        SBOM_API_URL = credentials('SBOM_API_URL')
        SBOM_API_KEY = credentials('SBOM_API_KEY')
        NODEJS_HOME = tool name: 'NodeJS-20', type: 'nodejs'
        PATH = "${NODEJS_HOME}/bin:${env.PATH}"
    }
    
    options {
        buildDiscarder(logRotator(numToKeepStr: '10'))
        timestamps()
        disableConcurrentBuilds()
    }
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
                script {
                    // Generate version folder with date and time
                    def shortSha = sh(script: "git rev-parse --short=8 HEAD", returnStdout:  true).trim()
                    def datePart = sh(script: "date +%Y-%m-%d", returnStdout: true).trim()
                    def timePart = sh(script: "date +%H-%M-%S", returnStdout: true).trim()
                    env.SHORT_SHA = shortSha
                    env.VERSION_FOLDER = "v${shortSha}_${datePart}_${timePart}"
                    env. FINAL_OUTPUT_PATH = "${env.OUTPUT_FOLDER}/${env.VERSION_FOLDER}"
                    
                    echo "🔧 Project: ${env.OUTPUT_FOLDER}"
                    echo "🔧 Version: ${env.VERSION_FOLDER}"
                }
            }
        }
        
        stage('Install Dependencies') {
            steps {
                sh '''
                    echo "📦 Installing cdxgen..."
                    npm install -g @cyclonedx/cdxgen
                    
                    echo "📦 Installing Grype..."
                    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b ${WORKSPACE}/bin
                    export PATH="${WORKSPACE}/bin:${PATH}"
                    ${WORKSPACE}/bin/grype version
                '''
            }
        }
        
        stage('Generate SBOM') {
            steps {
                sh '''
                    set -e
                    export PATH="${WORKSPACE}/bin:${PATH}"
                    
                    echo "🔧 Generating SBOM for ${OUTPUT_FOLDER} version ${VERSION_FOLDER}"
                    
                    mkdir -p "${FINAL_OUTPUT_PATH}"
                    
                    SBOM_FILE="${FINAL_OUTPUT_PATH}/sbom.json"
                    GRYPE_FILE="${FINAL_OUTPUT_PATH}/grype.json"
                    ENRICHED_SBOM="${FINAL_OUTPUT_PATH}/sbom-with-vulns.json"
                    
                    echo "📦 Running cdxgen..."
                    cdxgen "${TARGET_PATH}" -o "${SBOM_FILE}"
                    
                    echo "🛡️ Running Grype vulnerability scan..."
                    grype sbom:"${SBOM_FILE}" -o json > "${GRYPE_FILE}"
                    
                    echo "🧩 Merging SBOM with vulnerability data..."
                    jq -s '.[0] * {"grypeReport": .[1]}' \
                        "${SBOM_FILE}" \
                        "${GRYPE_FILE}" \
                        > "${ENRICHED_SBOM}"
                    
                    echo "✅ SBOM generation complete"
                    ls -la "${FINAL_OUTPUT_PATH}/"
                '''
            }
        }
        
        stage('Upload SBOM') {
            steps {
                withCredentials([string(credentialsId: 'SBOM_API_KEY', variable: 'JENKINS_API_KEY')]) {
                    sh '''
                        set -e
                        
                        SBOM_FILE="${FINAL_OUTPUT_PATH}/sbom.json"
                        GRYPE_FILE="${FINAL_OUTPUT_PATH}/grype.json"
                        ENRICHED_SBOM="${FINAL_OUTPUT_PATH}/sbom-with-vulns.json"
                        
                        echo "📤 Uploading SBOM to ${SBOM_API_URL}"
                        echo "📁 Version:  ${VERSION_FOLDER}"
                        
                        if [ -z "${JENKINS_API_KEY}" ]; then
                            echo "❌ Error: JENKINS_API_KEY is not set."
                            exit 1
                        fi
                        
                        if [ !  -f "${ENRICHED_SBOM}" ]; then
                            echo "❌ Error:  SBOM file not found at ${ENRICHED_SBOM}"
                            exit 1
                        fi
                        
                        echo "📄 SBOM file size: $(wc -c < "${ENRICHED_SBOM}") bytes"
                        
                        echo "📊 Preparing upload_payload.json..."
                        jq -n \
                            --arg folder "${OUTPUT_FOLDER}" \
                            --arg version "${VERSION_FOLDER}" \
                            --arg commit "${GIT_COMMIT}" \
                            --arg branch "${GIT_BRANCH}" \
                            --arg build_number "${BUILD_NUMBER}" \
                            --arg project "${JOB_NAME}" \
                            --arg projectUrl "${JOB_URL}" \
                            --slurpfile sbomWithVulns "${ENRICHED_SBOM}" \
                            --slurpfile sbomBase "${SBOM_FILE}" \
                            --slurpfile grype "${GRYPE_FILE}" \
                            '{
                                folder: $folder,
                                version:  $version,
                                metadata:  {
                                    commit: $commit,
                                    branch:  $branch,
                                    buildNumber: $build_number,
                                    project: $project,
                                    projectUrl: $projectUrl,
                                    source: "jenkins",
                                    uploadedAt: now | todate
                                },
                                files: [
                                    { filename: "sbom-with-vulns.json", content: $sbomWithVulns[0] },
                                    { filename: "sbom.json", content: $sbomBase[0] },
                                    { filename: "grype.json", content: $grype[0] }
                                ]
                            }' > upload_payload.json
                        
                        echo "🚀 Uploading..."
                        RESPONSE=$(curl -sS -k -w "\n%{http_code}" \
                            -X POST "${SBOM_API_URL}" \
                            -H "Content-Type: application/json" \
                            -H "X-API-Key: ${JENKINS_API_KEY}" \
                            --data-binary @upload_payload.json \
                            --max-time 120)
                        
                        HTTP_CODE=$(echo "${RESPONSE}" | tail -n1)
                        BODY=$(echo "${RESPONSE}" | sed '$d')
                        
                        echo "📡 Response code: ${HTTP_CODE}"
                        echo "📋 Response body: ${BODY}"
                        
                        if [ "${HTTP_CODE}" -ge 200 ] && [ "${HTTP_CODE}" -lt 300 ]; then
                            echo "✅ SBOM uploaded successfully!"
                        else
                            echo "❌ Failed to upload SBOM (HTTP ${HTTP_CODE})"
                            exit 1
                        fi
                    '''
                }
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: "${OUTPUT_FOLDER}/${VERSION_FOLDER}/*.json", allowEmptyArchive: true
        }
        success {
            echo "✅ SBOM Pipeline completed successfully!"
        }
        failure {
            echo "❌ SBOM Pipeline failed!"
        }
        cleanup {
            cleanWs()
        }
    }
}
