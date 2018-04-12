// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
/**                                                                                           //
 * Copyright (c) 2013-2018, The Kovri I2P Router Project                                      //
 *                                                                                            //
 * All rights reserved.                                                                       //
 *                                                                                            //
 * Redistribution and use in source and binary forms, with or without modification, are       //
 * permitted provided that the following conditions are met:                                  //
 *                                                                                            //
 * 1. Redistributions of source code must retain the above copyright notice, this list of     //
 *    conditions and the following disclaimer.                                                //
 *                                                                                            //
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list     //
 *    of conditions and the following disclaimer in the documentation and/or other            //
 *    materials provided with the distribution.                                               //
 *                                                                                            //
 * 3. Neither the name of the copyright holder nor the names of its contributors may be       //
 *    used to endorse or promote products derived from this software without specific         //
 *    prior written permission.                                                               //
 *                                                                                            //
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY        //
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF    //
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL     //
 * THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,       //
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,               //
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS    //
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,          //
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF    //
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.               //
 *                                                                                            //
 * Parts of the project are originally copyright (c) 2013-2015 The PurpleI2P Project          //
 */

#include "core/router/lease_set.h"

#include <cstring>

#include "core/crypto/rand.h"

#include "core/router/net_db/impl.h"
#include "core/router/tunnel/pool.h"

#include "core/util/log.h"
#include "core/util/timestamp.h"

namespace kovri {
namespace core {

LeaseSet::LeaseSet(
    const std::uint8_t* buf,
    std::size_t len)
    : m_IsValid(true),
      m_Buffer{buf, buf + len} {
  ReadFromBuffer();
}

LeaseSet::LeaseSet(
    const kovri::core::TunnelPool& pool)
    : m_IsValid(true),
      m_Buffer(MAX_LS_BUFFER_SIZE)
{
  // header
  const kovri::core::LocalDestination* local_destination = pool.GetLocalDestination();
  if (!local_destination) {
    m_IsValid = false;
    LOG(error) << "LeaseSet: destination for local LeaseSet doesn't exist";
    return;
  }
  std::size_t buffer_len = local_destination->GetIdentity().ToBuffer(
      m_Buffer.data(),
      MAX_LS_BUFFER_SIZE);
  memcpy(
      m_Buffer.data() + buffer_len,
      local_destination->GetEncryptionPublicKey(),
      256);
  buffer_len += 256;
  const auto signing_key_len = local_destination->GetIdentity().GetSigningPublicKeyLen();
  memset(m_Buffer.data() + buffer_len, 0, signing_key_len);
  buffer_len += signing_key_len;
  auto tunnels = pool.GetInboundTunnels(5);  // 5 tunnels maximum
  m_Buffer[buffer_len] = tunnels.size();  // num leases
  buffer_len++;
  // leases
  for (auto& it : tunnels) {
    memcpy(m_Buffer.data() + buffer_len, it->GetNextIdentHash(), 32);
    buffer_len += 32;  // gateway id
    core::OutputByteStream::Write<std::uint32_t>(
        m_Buffer.data() + buffer_len, it->GetNextTunnelID());
    buffer_len += 4;  // tunnel id
    std::uint64_t ts =
      it->GetCreationTime() +
      kovri::core::TUNNEL_EXPIRATION_TIMEOUT -
      kovri::core::TUNNEL_EXPIRATION_THRESHOLD;  // 1 minute before expiration
    ts *= 1000;  // in milliseconds
    ts += kovri::core::RandInRange32(0, 5);  // + random milliseconds
    core::OutputByteStream::Write<std::uint64_t>(
        m_Buffer.data() + buffer_len, ts);
    buffer_len += 8;  // end date
  }
  // signature
  local_destination->Sign(
      m_Buffer.data(),
      buffer_len,
      m_Buffer.data() + buffer_len);
  buffer_len += local_destination->GetIdentity().GetSignatureLen();
  LOG(debug)
    << "LeaseSet: local LeaseSet of " << tunnels.size() << " leases created";

  m_Buffer.resize(buffer_len);
  ReadFromBuffer();
}

void LeaseSet::Update(
    const std::uint8_t* buf,
    std::size_t len) {
  m_Leases.clear();
  m_Buffer.assign(buf, buf + len);
  ReadFromBuffer();
}

void LeaseSet::ReadFromBuffer() {
  std::size_t size = m_Identity.FromBuffer(m_Buffer.data(), m_Buffer.size());
  memcpy(m_EncryptionKey.data(), m_Buffer.data() + size, 256);
  size += 256;  // encryption key
  size += m_Identity.GetSigningPublicKeyLen();  // unused signing key
  const std::uint8_t num = m_Buffer[size];
  size++;  // num
  LOG(debug) << "LeaseSet: num=" << static_cast<int>(num);
  if (!num)
    m_IsValid = false;
  // process leases
  const std::uint8_t* leases = m_Buffer.data() + size;
  m_Leases.reserve(num);
  for (int i = 0; i < num; i++) {
    Lease lease;
    lease.tunnel_gateway = leases;
    leases += 32;  // gateway
    lease.tunnel_ID = core::InputByteStream::Read<std::uint32_t>(leases);
    leases += 4;  // tunnel ID
    lease.end_date = core::InputByteStream::Read<std::uint64_t>(leases);
    leases += 8;  // end date
    m_Leases.push_back(lease);
    // check if lease's gateway is in our netDb
    if (!netdb.FindRouter(lease.tunnel_gateway)) {
      // if not found request it
      LOG(debug) << "LeaseSet: lease's tunnel gateway not found, requesting";
      netdb.RequestDestination(lease.tunnel_gateway);
    }
  }
  // verify
  if (!m_Identity.Verify(m_Buffer.data(), leases - m_Buffer.data(), leases)) {
    LOG(warning) << "LeaseSet: verification failed";
    m_IsValid = false;
  }
}

std::vector<Lease> LeaseSet::GetNonExpiredLeases(
    bool with_threshold) const {
  const auto ts = kovri::core::GetMillisecondsSinceEpoch();
  std::vector<Lease> leases;

  const auto threshold = with_threshold ? 0 : kovri::core::TUNNEL_EXPIRATION_THRESHOLD * 1000;

  std::copy_if(m_Leases.begin(), m_Leases.end(), std::back_inserter(leases),
    [threshold, ts](const Lease& lease)
  {
    return ts < lease.end_date - threshold;
  });

  return leases;
}

bool LeaseSet::HasExpiredLeases() const {
  const auto ts = kovri::core::GetMillisecondsSinceEpoch();

  return std::any_of(m_Leases.begin(), m_Leases.end(), 
    [ts](const Lease& lease)
  {
    return ts >= lease.end_date;
  });
}

bool LeaseSet::HasNonExpiredLeases() const {
  const auto ts = kovri::core::GetMillisecondsSinceEpoch();
  return std::any_of(m_Leases.begin(), m_Leases.end(), 
    [ts](const Lease& lease)
  {
    return ts < lease.end_date;
  });
}

}  // namespace core
}  // namespace kovri
