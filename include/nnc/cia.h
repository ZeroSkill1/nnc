/** \file   cia.h
 *  \brief  Functions relating to CIA.
 *  \see    https://www.3dbrew.org/wiki/CIA
 */
#ifndef inc_nnc_cia_h
#define inc_nnc_cia_h

#include <nnc/read-stream.h>
#include <nnc/crypto.h>
#include <nnc/base.h>
#include <nnc/tmd.h>
NNC_BEGIN

/** \cond INTERNAL */
/* blame ninty for this mess of a macro */
#define NNC__FOREACH_CINDEX_IMPL2(index, cindex, line) \
		for(int mnnc__i##line = 0; mnnc__i##line != 0x2000; ++mnnc__i##line) \
			for(int mnnc__j##line = 7; mnnc__j##line != -1; --mnnc__j##line) \
				if((cindex)[mnnc__i##line] & (1 << mnnc__j##line) && (index = mnnc__i##line * 8 + (7 - mnnc__j##line), 1))
#define NNC__FOREACH_CINDEX_IMPL1(index, cindex, line) NNC__FOREACH_CINDEX_IMPL2(index, cindex, line)
/** \endcond */
/** \brief Iterate over all indices in a content index.
 *  \code
 *  nnc_u32 index;
 *  NNC_FOREACH_CINDEX(index, cia_header.content_index)
 *    // ...
 *  \endcode
 */
#define NNC_FOREACH_CINDEX(index, cindex) NNC__FOREACH_CINDEX_IMPL1(index, cindex, __LINE__)

/** \brief Tests if \p cindex has \p index. */
#define NNC_CINDEX_HAS(cindex, index) \
	((cindex)[(index) / 8] & (1 << (7 - ((index) % 8))))


typedef struct nnc_cia_header {
	nnc_u16 type;                 ///< Type (?).
	nnc_u16 version;              ///< CIA format version.
	nnc_u32 cert_chain_size;      ///< Size of the certificate chain section.
	nnc_u32 ticket_size;          ///< Size of the ticket section.
	nnc_u32 tmd_size;             ///< Size of the TMD section.
	nnc_u32 meta_size;            ///< Size of the meta section, may be 0.
	nnc_u64 content_size;         ///< Size of the contents section.
	nnc_u8 content_index[0x2000]; ///< Contents preset in the CIA, see \ref NNC_FOREACH_CINDEX and \ref NNC_CINDEX_HAS for usage.
} nnc_cia_header;

typedef struct nnc_cia_content_reader {
	nnc_chunk_record *chunks;
	nnc_u16 content_count;
	nnc_cia_header *cia;
	nnc_u8 key[0x10];
	nnc_rstream *rs;
} nnc_cia_content_reader;

/** A pseudo-stream to hold all possible required streams, yet still
 *  usable like all other streams with \ref NNC_RSP */
typedef struct nnc_cia_content_stream {
	union nnc_cia_content_stream_union {
		struct nnc_cia_content_stream_enc {
			nnc_aes_cbc crypt;
			nnc_subview sv;
		} enc; ///< Used when the content is encrypted.
		struct nnc_cia_content_stream_dec {
			nnc_subview sv;
		} dec; ///< Used when the content is decrypted.
	} u;
} nnc_cia_content_stream;

/** \brief      Reads the header of a CIA.
 *  \param rs   Stream to read CIA from.
 *  \param cia  Output CIA.
 *  \returns
 *  Anything rstream read can return.
 */
nnc_result nnc_read_cia_header(nnc_rstream *rs, nnc_cia_header *cia);

/** \brief      Open a subview of the certificate chain section.
 *  \param cia  CIA to open certificate chain of.
 *  \param rs   Associated read stream.
 *  \param sv   Output subview.
 *  \returns
 *  This function always returns NNC_R_OK currently.
 */
nnc_result nnc_cia_open_certchain(nnc_cia_header *cia, nnc_rstream *rs, nnc_subview *sv);

/** \brief      Open a subview of the ticket section.
 *  \param cia  CIA to open ticket of.
 *  \param rs   Associated read stream.
 *  \param sv   Output subview.
 *  \returns
 *  This function always returns NNC_R_OK currently.
 */
nnc_result nnc_cia_open_ticket(nnc_cia_header *cia, nnc_rstream *rs, nnc_subview *sv);

/** \brief      Open a subview of the TMD section.
 *  \param cia  CIA to open TMD of.
 *  \param rs   Associated read stream.
 *  \param sv   Output subview.
 *  \returns
 *  This function always returns NNC_R_OK currently.
 */
nnc_result nnc_cia_open_tmd(nnc_cia_header *cia, nnc_rstream *rs, nnc_subview *sv);

/** \brief      Open a subview of the meta section.
 *  \param cia  CIA to open meta of.
 *  \param rs   Associated read stream.
 *  \param sv   Output subview.
 *  \returns
 *  \p NNC_R_NOT_FOUND => CIA doesn't have a meta section.
 */
nnc_result nnc_cia_open_meta(nnc_cia_header *cia, nnc_rstream *rs, nnc_subview *sv);

/** \brief         Open a CIA for content reading.
 *  \param cia     Stream to make reader of.
 *  \param rs      Associated read stream.
 *  \param ks      Keyset from \ref nnc_keyset_default.
 *  \param reader  Output reader.
 *  \note          The \p cia and \p rs pointers must stay valid for the extent of the reader being used.
 *  \note          You must free up the used memory with \ref nnc_cia_free_reader.
 *  \note          If this function does not return NNC_R_OK you musn't call \ref nnc_cia_free_reader.
 *  \returns
 *  Anything \ref nnc_read_tmd_header can return. \n
 *  Anything \ref nnc_read_tmd_chunk_records can return. \n
 *  Anything \ref nnc_read_ticket can return. \n
 *  Anything \ref nnc_decrypt_tkey can return. \n
 *  \p NNC_R_NOMEM => Failed to allocate dynamic memory.
 */
nnc_result nnc_cia_make_reader(nnc_cia_header *cia, nnc_rstream *rs,
	nnc_keyset *ks, nnc_cia_content_reader *reader);

/** \brief          Get a subview of a content.
 *  \param reader   Reader to get subview of.
 *  \param index    Content index, you may test if it exists beforehand with \ref NNC_CINDEX_HAS, you can iterate over all contents with \ref NNC_FOREACH_CINDEX.
 *  \param content  Output content stream.
 *  \param chunk    Optionally you can save a pointer to the used chunk record.
 *  \returns
 *  Anything \ref nnc_aes_cbc_open an return. \n
 *  \p NNC_R_NOT_FOUND => Content index is not present in the TMD.
 */
nnc_result nnc_cia_open_content(nnc_cia_content_reader *reader, nnc_u16 index,
	nnc_cia_content_stream *content, nnc_chunk_record **chunk);

/** \brief         Free memory allocated by \ref nnc_cia_make_reader
 *  \param reader  Reader to free memory of.
 */
void nnc_cia_free_reader(nnc_cia_content_reader *reader);

NNC_END
#endif

