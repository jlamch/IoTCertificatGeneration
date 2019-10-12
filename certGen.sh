## Copyright (c) Microsoft. All rights reserved.
## Licensed under the MIT license. See LICENSE file in the project root for full license information.

###############################################################################
# This script demonstrates creating X.509 certificates for an Azure IoT Hub
# CA Cert deployment.
#
# These certs MUST NOT be used in production.  It is expected that production
# certificates will be created using a company's proper secure signing process.
# These certs are intended only to help demonstrate and prototype CA certs.
###############################################################################

root_ca_dir="."
home_dir="."
algorithm="genrsa"
COUNTRY="PL"
STATE="WA"
LOCALITY="Katowice"
ORGANIZATION_NAME="JoannaLamch"
root_ca_password="jl1234"
key_bits_length="4096"
days_till_expire=365
ca_chain_prefix="azure-iot-jl.chain.ca"
intermediate_ca_dir="."
openssl_root_config_file="./openssl_root_ca.cnf"
root_ca_prefix="azure-iot-jl.root.ca"

function makeCNsubject()
{
    local result="/CN=${1}"
    case $OSTYPE in
        msys|win32) result="/${result}"
    esac
    echo "$result"
}

function generate_root_ca()
{
    local common_name="IoT Hub CA Cert Joanna Lamch"
    local password_cmd=" -aes256 -passout pass:${root_ca_password} "

    cd ${home_dir}
    echo "Creating the Root CA Private Key"

    openssl ${algorithm} \
            ${password_cmd} \
            -out ${root_ca_dir}/private/${root_ca_prefix}.key.pem \
            ${key_bits_length}
    [ $? -eq 0 ] || exit $?
    chmod 400 ${root_ca_dir}/private/${root_ca_prefix}.key.pem
    [ $? -eq 0 ] || exit $?

    echo "Creating the Root CA Certificate"
    password_cmd=" -passin pass:${root_ca_password} "

    openssl req \
            -new \
            -x509 \
            -config ${openssl_root_config_file} \
            ${password_cmd} \
            -key ${root_ca_dir}/private/${root_ca_prefix}.key.pem \
            -subj "$(makeCNsubject "${common_name}")" \
            -days ${days_till_expire} \
            -sha256 \
            -extensions v3_ca \
            -out ${root_ca_dir}/certs/${root_ca_prefix}.cert.pem
    [ $? -eq 0 ] || exit $?
    chmod 444 ${root_ca_dir}/certs/${root_ca_prefix}.cert.pem
    [ $? -eq 0 ] || exit $?

    echo "CA Root Certificate Generated At:"
    echo "---------------------------------"
    echo "    ${root_ca_dir}/certs/${root_ca_prefix}.cert.pem"
    echo ""
    openssl x509 -noout -text \
            -in ${root_ca_dir}/certs/${root_ca_prefix}.cert.pem

    [ $? -eq 0 ] || exit $?
}

###############################################################################
#  Creates required directories and removes left over cert files.
#  Run prior to creating Root CA; after that these files need to persist.
###############################################################################
function prepare_filesystem()
{
    if [ ! -f ${openssl_root_config_file} ]; then
        echo "Missing file ${openssl_root_config_file}"
        exit 1
    fi

    rm -rf csr
    rm -rf private
    rm -rf certs
    rm -rf intermediateCerts
    rm -rf newcerts

    mkdir -p csr
    mkdir -p private
    mkdir -p certs
    mkdir -p intermediateCerts
    mkdir -p newcerts

    rm -f ./index.txt
    touch ./index.txt

    rm -f ./serial
    echo 01 > ./serial
}

###############################################################################
# Generate a certificate for a leaf device
# signed with either the root or intermediate cert.
###############################################################################
function generate_leaf_certificate()
{
    local common_name="${1}"
    local device_prefix="${2}"
    local certificate_dir="${3}"
    local ca_password="${4}"
    local openssl_config_file="${5}"

    generate_device_certificate_common "${common_name}" "${device_prefix}" \
                                       "${certificate_dir}" "${ca_password}" \
                                       "${openssl_config_file}" "server_cert" \
                                       "Leaf Device"    
}

###############################################################################
# Generate a Certificate for a device using specific openssl extension and
# signed with either the root or intermediate cert.
###############################################################################
function generate_device_certificate_common()
{
    local common_name="${1}"
    local device_prefix="${2}"
    local certificate_dir="${3}"
    local ca_password="${4}"
    local server_pfx_password="1234"
    local password_cmd=" -passin pass:${ca_password} "
    local openssl_config_file="${5}"
    local openssl_config_extension="${6}"
    local cert_type_diagnostic="${7}"

    echo "Creating ${cert_type_diagnostic} Certificate"
    echo "----------------------------------------"
    cd ${home_dir}

    openssl ${algorithm} \
            -out ${certificate_dir}/private/${device_prefix}.key.pem \
            ${key_bits_length}
    [ $? -eq 0 ] || exit $?
    chmod 444 ${certificate_dir}/private/${device_prefix}.key.pem
    [ $? -eq 0 ] || exit $?

    echo "Create the ${cert_type_diagnostic} Certificate Request"
    echo "----------------------------------------"
    openssl req -config ${openssl_config_file} \
        -key ${certificate_dir}/private/${device_prefix}.key.pem \
        -subj "$(makeCNsubject "${common_name}")" \
        -new -sha256 -out ${certificate_dir}/csr/${device_prefix}.csr.pem
    [ $? -eq 0 ] || exit $?

    openssl ca -batch -config ${openssl_config_file} \
            ${password_cmd} \
            -extensions "${openssl_config_extension}" \
            -days ${days_till_expire} -notext -md sha256 \
            -in ${certificate_dir}/csr/${device_prefix}.csr.pem \
            -out ${certificate_dir}/certs/${device_prefix}.cert.pem
    [ $? -eq 0 ] || exit $?
    chmod 444 ${certificate_dir}/certs/${device_prefix}.cert.pem
    [ $? -eq 0 ] || exit $?

    echo "Verify signature of the ${cert_type_diagnostic}" \
         " certificate with the signer"
    echo "-----------------------------------"
    openssl verify \
            -CAfile ${certificate_dir}/certs/${ca_chain_prefix}.cert.pem \
            ${certificate_dir}/certs/${device_prefix}.cert.pem
    [ $? -eq 0 ] || exit $?

    echo "${cert_type_diagnostic} Certificate Generated At:"
    echo "----------------------------------------"
    echo "    ${certificate_dir}/certs/${device_prefix}.cert.pem"
    echo ""
    openssl x509 -noout -text \
            -in ${certificate_dir}/certs/${device_prefix}.cert.pem
    [ $? -eq 0 ] || exit $?
    echo "Create the ${cert_type_diagnostic} PFX Certificate"
    echo "----------------------------------------"
    openssl pkcs12 -in ${certificate_dir}/certs/${device_prefix}.cert.pem \
            -inkey ${certificate_dir}/private/${device_prefix}.key.pem \
            -password pass:${server_pfx_password} \
            -export -out ${certificate_dir}/certs/${device_prefix}.cert.pfx
    [ $? -eq 0 ] || exit $?
    echo "${cert_type_diagnostic} PFX Certificate Generated At:"
    echo "--------------------------------------------"
    echo "    ${certificate_dir}/certs/${device_prefix}.cert.pfx"
    [ $? -eq 0 ] || exit $?

    cat ${certificate_dir}/certs/${device_prefix}.cert.pem \
        ${intermediate_ca_dir}/certs/${intermediate_ca_prefix}.cert.pem \
        ${root_ca_dir}/certs/${root_ca_prefix}.cert.pem > \
        ${certificate_dir}/certs/${device_prefix}-full-chain.cert.pem 

}

###############################################################################
# Generates a root and intermediate certificate for CA certs.
###############################################################################
function initial_cert_generation()
{
    prepare_filesystem
    generate_root_ca
}

###############################################################################
# Generates a certificate for verification, chained directly to the root.
###############################################################################
function generate_verification_certificate()
{
    if [$# -ne 1]; then
        echo "Usage: <subjectName>"
        exit 1
    fi

    rm -f ./private/verification-code.key.pem
    rm -f ./certs/verification-code.cert.pem
    generate_leaf_certificate "${1}" "verification-code" \
                              ${root_ca_dir} ${root_ca_password} \
                              ${openssl_root_config_file}
}

if [ "${1}" == "create_root" ]; then
    initial_cert_generation
elif [ "${1}" == "create_verification_certificate" ]; then
    generate_verification_certificate "${2}"
else
    echo "Usage: create_root                                    # Creates a new root certificates"
    echo "       create_verification_certificate <subjectName>  # Creates a verification certificate, signed with <subjectName>"
    exit 1
fi
