import 'dart:typed_data';
import 'package:collection/collection.dart';
import '../rtp/packet.dart';
import 'crypto_gcm.dart';
import 'protection_profiles.dart';

const int seqNumMax = 1 << 16;
const int seqNumMedian = seqNumMax >> 1;

class SRTPContext {
  final ProtectionProfile protectionProfile;
  final SRTP gcm;
  final Map<int, SRTPSsrcState> _srtpSsrcStates = {};

  SRTPContext({required this.protectionProfile, required this.gcm});

  SRTPSsrcState _getSRTPSsrcState(int ssrc) {
    return _srtpSsrcStates.putIfAbsent(ssrc, () => SRTPSsrcState(ssrc));
  }

  Future<Uint8List?> decryptRTPPacket(
      Uint8List buf, int offset, int arrayLen) async {
    RtpPacket? packet = RtpPacket.decodePacket(buf, offset, arrayLen);

    final state = _getSRTPSsrcState(packet!.header.ssrc);
    final roc = state.nextRolloverCount(packet.header.sequenceNumber);
    final result = await gcm.decrypt(buf, buf, roc);
    if (result == null) return null;
    return result.sublist(packet.headerSize);
  }
}

class SRTPSsrcState {
  final int ssrc;
  int index = 0;
  bool rolloverHasProcessed = false;

  SRTPSsrcState(this.ssrc);

  int nextRolloverCount(int sequenceNumber) {
    final localRoc = index >> 16;
    final localSeq = index & (seqNumMax - 1);
    int guessRoc = localRoc;
    int difference = 0;

    if (rolloverHasProcessed) {
      if (index > seqNumMedian) {
        if (localSeq < seqNumMedian) {
          if (sequenceNumber - localSeq > seqNumMedian) {
            guessRoc = localRoc - 1;
            difference = sequenceNumber - localSeq - seqNumMax;
          } else {
            difference = sequenceNumber - localSeq;
          }
        } else {
          if (localSeq - seqNumMedian > sequenceNumber) {
            guessRoc = localRoc + 1;
            difference = sequenceNumber - localSeq + seqNumMax;
          } else {
            difference = sequenceNumber - localSeq;
          }
        }
      } else {
        difference = sequenceNumber - localSeq;
      }
    }

    if (!rolloverHasProcessed) {
      index |= sequenceNumber;
      rolloverHasProcessed = true;
    } else if (difference > 0) {
      index += difference;
    }

    return guessRoc;
  }
}
