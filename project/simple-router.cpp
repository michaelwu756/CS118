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
    newArp.arp_sip = htons(newArp.arp_sip);
    newArp.arp_tip = htonl(newArp.arp_tip);
    for (size_t i = 0; i < sizeof(arp_hdr); i++) {
      newPacket[sizeof(ethernet_hdr)+i] = ((unsigned char *)&newArp)[i];
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

  void printEthernetHeader(const ethernet_hdr& header) {
    std::cerr << "Destination Address: ";
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
      std::cerr << std::hex << (int)header.ether_dhost[i] << " ";
    }
    std::cerr << "Source Address: ";
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
      std::cerr << std::hex << (int)header.ether_shost[i] << " ";
    }
    std::cerr << "Type: " << std::to_string(header.ether_type) << std::endl;
  }

  bool broadcastAddress(Buffer mac) {
    return mac[0] == 0xff && mac[1] == 0xff && mac[2] == 0xff && mac[3] == 0xff && mac[4] == 0xff && mac[5] == 0xff;
  }

  void SimpleRouter::handleARPPacket(const Buffer& packet, const Interface* iface) {
    arp_hdr arp = extractArpHeader(packet);
    if (arp.arp_op == arp_op_request && arp.arp_tip == iface->ip) {
        for (int i = 0; i < ETHER_ADDR_LEN; i++) {
          arp.arp_tha[i] = iface->addr[i];
        }
        arp.arp_op = arp_op_reply;
        ethernet_hdr newHeader = extractEthernetHeader(packet);
        for (int i = 0; i < ETHER_ADDR_LEN; i++) {
          newHeader.ether_dhost[i] = arp.arp_sha[i];
          newHeader.ether_shost[i] = iface->addr[i];
        }
        sendPacket(replaceEthernetHeader(newHeader, replaceArpHeader(arp, packet)), iface->name);
    }
    else if (arp.arp_op == arp_op_reply) {
      //record in arp cache
      //send queued packets
    }
  }

  void SimpleRouter::handleIPPacket(const Buffer& packet, const Interface* iface) {
    ip_hdr ip = extractIpHeader(packet);
    for (const auto& localInterface : m_ifaces) {
      if (ip.ip_dst == localInterface.ip) {
        return;
      }
    }
    //verify checksum & minimum length
    //find subnet
    //ARP table lookup
    //ARP request
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

    std::cerr << "Address: ";
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
      std::cerr << std::hex << (int)incomingIface->addr[i] << " ";
    }
    std::cerr << std::endl;

    ethernet_hdr ethernetHeader = extractEthernetHeader(packet);
    printEthernetHeader(ethernetHeader);

    Buffer mac = getEthernetDestMac(ethernetHeader);
    if (broadcastAddress(mac) || mac == incomingIface->addr) {
      if (ethernetHeader.ether_type == ethertype_arp) {
        std::cerr << "This is an ARP Packet" << std::endl;
        handleARPPacket(packet, incomingIface);
      }
      else if (ethernetHeader.ether_type == ethertype_ip) {
        std::cerr << "This is an IPv4 Packet" << std::endl;
        handleIPPacket(packet, incomingIface);
      }
      else {
        std::cerr << "This is an unknown packet type" << std::endl;
      }
    }
    else {
      std::cerr << "Unknown Destination Mac Address" << std::endl;
    }

    std::cerr << getRoutingTable() << std::endl;
    printIfaces(std::cerr);
  }
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

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

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}


} // namespace simple_router {
