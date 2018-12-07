/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router {

  Buffer replaceEthernetHeader(const ethernet_hdr& eth, const Buffer& packet) {
    Buffer newPacket = packet;
    ethernet_hdr newEth = eth;
    newEth.ether_type = htons(newEth.ether_type);
    for (size_t i = 0; i < sizeof(ethernet_hdr); i++) {
      newPacket[i] = ((unsigned char*)&newEth)[i];
    }
    return newPacket;
  }

  ethernet_hdr extractEthernetHeader(const Buffer& packet) {
    unsigned char arr[sizeof(ethernet_hdr)];
    for (size_t i = 0; i < sizeof(ethernet_hdr); i++) {
      arr[i] = packet[i];
    }
    ethernet_hdr* ptr = reinterpret_cast<ethernet_hdr*>(&arr);
    ptr->ether_type = ntohs(ptr->ether_type);
    return *ptr;
  }

  Buffer getEthernetDestMac(const ethernet_hdr& header) {
    Buffer buf;
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
      buf.push_back(header.ether_dhost[i]);
    }
    return buf;
  }

  Buffer replaceArpHeader(const arp_hdr& arp, const Buffer& packet) {
    Buffer newPacket = packet;
    arp_hdr newArp = arp;
    newArp.arp_hrd = htons(newArp.arp_hrd);
    newArp.arp_pro = htons(newArp.arp_pro);
    newArp.arp_op = htons(newArp.arp_op);
    newArp.arp_sip = htonl(newArp.arp_sip);
    newArp.arp_tip = htonl(newArp.arp_tip);
    for (size_t i = 0; i < sizeof(arp_hdr); i++) {
      newPacket[sizeof(ethernet_hdr) + i] = ((unsigned char*)&newArp)[i];
    }
    return newPacket;
  }

  arp_hdr extractArpHeader(const Buffer& packet) {
    unsigned char arr[sizeof(arp_hdr)];
    for (size_t i = 0; i < sizeof(arp_hdr); i++) {
      arr[i] = packet[sizeof(ethernet_hdr) + i];
    }
    arp_hdr* ptr = reinterpret_cast<arp_hdr*>(&arr);
    ptr->arp_hrd = ntohs(ptr->arp_hrd);
    ptr->arp_pro = ntohs(ptr->arp_pro);
    ptr->arp_op = ntohs(ptr->arp_op);
    ptr->arp_sip = ntohl(ptr->arp_sip);
    ptr->arp_tip = ntohl(ptr->arp_tip);
    return *ptr;
  }

  Buffer getArpSourceMac(const arp_hdr& header) {
    Buffer buf;
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
      buf.push_back(header.arp_sha[i]);
    }
    return buf;
  }

  Buffer replaceIpHeader(const ip_hdr& ip, const Buffer& packet) {
    Buffer newPacket = packet;
    ip_hdr newIp = ip;
    newIp.ip_len = htons(newIp.ip_len);
    newIp.ip_id = htons(newIp.ip_id);
    newIp.ip_off = htons(newIp.ip_off);
    newIp.ip_sum = htons(newIp.ip_sum);
    newIp.ip_src = htonl(newIp.ip_src);
    newIp.ip_dst = htonl(newIp.ip_dst);
    for (size_t i = 0; i < sizeof(ip_hdr); i++) {
      newPacket[sizeof(ethernet_hdr) + i] = ((unsigned char*)&newIp)[i];
    }
    return newPacket;
  }

  ip_hdr extractIpHeader(const Buffer& packet) {
    unsigned char arr[sizeof(ip_hdr)];
    for (size_t i = 0; i < sizeof(ip_hdr); i++) {
      arr[i] = packet[sizeof(ethernet_hdr) + i];
    }
    ip_hdr* ptr = reinterpret_cast<ip_hdr*>(&arr);
    ptr->ip_len = ntohs(ptr->ip_len);
    ptr->ip_id = ntohs(ptr->ip_id);
    ptr->ip_off = ntohs(ptr->ip_off);
    ptr->ip_sum = ntohs(ptr->ip_sum);
    ptr->ip_src = ntohl(ptr->ip_src);
    ptr->ip_dst = ntohl(ptr->ip_dst);
    return *ptr;
  }

  bool broadcastAddress(Buffer mac) {
    return mac[0] == 0xff && mac[1] == 0xff && mac[2] == 0xff && mac[3] == 0xff && mac[4] == 0xff && mac[5] == 0xff;
  }

  uint16_t computeIpChecksum(const ip_hdr& ip) {
    uint32_t sum = 0;
    sum += (ip.ip_v << 12) + (ip.ip_hl << 8);
    sum += ip.ip_tos;
    sum += ip.ip_len;
    sum += ip.ip_id;
    sum += ip.ip_off;
    sum += (ip.ip_ttl << 8) + ip.ip_p;
    sum += (ip.ip_src >> 16) + (ip.ip_src & 0xffff);
    sum += (ip.ip_dst >> 16) + (ip.ip_dst & 0xffff);
    sum = 0xffff & ~((0xffff & sum) + ((0xffff0000 & sum) >> 16));
    return sum;
  }

  bool verifyIpChecksum(const ip_hdr& ip) {
    return computeIpChecksum(ip) == ip.ip_sum;
  }

  void SimpleRouter::handleARPPacket(const Buffer& packet, const Interface* iface) {
    arp_hdr arp = extractArpHeader(packet);
    if (arp.arp_op == arp_op_request && arp.arp_tip == iface->ip) {
      for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        arp.arp_tha[i] = arp.arp_sha[i];
        arp.arp_sha[i] = iface->addr[i];
      }
      arp.arp_op = arp_op_reply;
      uint32_t temp = arp.arp_sip;
      arp.arp_sip = arp.arp_tip;
      arp.arp_tip = temp;
      ethernet_hdr newHeader = extractEthernetHeader(packet);
      for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        newHeader.ether_dhost[i] = arp.arp_tha[i];
        newHeader.ether_shost[i] = iface->addr[i];
      }
      sendPacket(replaceEthernetHeader(newHeader, replaceArpHeader(arp, packet)), iface->name);
    }
    else if (arp.arp_op == arp_op_reply) {
      Buffer mac = getArpSourceMac(arp);
      std::shared_ptr<ArpRequest> req = m_arp.insertArpEntry(mac, arp.arp_sip);
      if (req != nullptr) {
        m_arp.removeRequest(req);
        for (const auto& pending : req->packets) {
          const Interface* packetIface = findIfaceByName(pending.iface);
          ethernet_hdr newHeader;
          for (int i = 0; i < ETHER_ADDR_LEN; i++) {
            newHeader.ether_dhost[i] = mac[i];
            newHeader.ether_shost[i] = packetIface->addr[i];
          }
          newHeader.ether_type = ethertype_ip;
          sendPacket(replaceEthernetHeader(newHeader, pending.packet), pending.iface);
        }
      }
    }
  }

  void SimpleRouter::handleIPPacket(const Buffer& packet) {
    ip_hdr ip = extractIpHeader(packet);
    if (ip.ip_len < 20 || !verifyIpChecksum(ip)) {
      return;
    }
    for (const auto& localInterface : m_ifaces) {
      if (ip.ip_dst == localInterface.ip) {
        return;
      }
    }
    ip.ip_ttl = ip.ip_ttl - 1;
    if (ip.ip_ttl == 0) {
      return;
    }
    ip.ip_sum = computeIpChecksum(ip);
    Buffer newIpPacket = replaceIpHeader(ip, packet);
    const Interface* iface = findIfaceByName(m_routingTable.lookup(ip.ip_dst).ifName);
    std::shared_ptr<ArpEntry> arpEntry = m_arp.lookup(ip.ip_dst);
    if (arpEntry == nullptr) {
      m_arp.queueRequest(ip.ip_dst, newIpPacket, iface->name);
    }
    else {
      ethernet_hdr eth;
      for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        eth.ether_dhost[i] = arpEntry->mac[i];
        eth.ether_shost[i] = iface->addr[i];
      }
      eth.ether_type = ethertype_ip;
      sendPacket(replaceEthernetHeader(eth, newIpPacket), iface->name);
    }
  }

  void SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
  {
    std::cerr << std::endl;
    std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

    const Interface* incomingIface = findIfaceByName(inIface);
    if (incomingIface == nullptr) {
      std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
      return;
    }

    ethernet_hdr ethernetHeader = extractEthernetHeader(packet);
    Buffer mac = getEthernetDestMac(ethernetHeader);
    if (broadcastAddress(mac) || mac == incomingIface->addr) {
      if (ethernetHeader.ether_type == ethertype_arp) {
        handleARPPacket(packet, incomingIface);
      }
      else if (ethernetHeader.ether_type == ethertype_ip) {
        handleIPPacket(packet);
      }
    }
  }
// You should not need to touch the rest of this code.

SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ntohl(ip->second)));
  }

  printIfaces(std::cerr);
}


} // namespace simple_router {
