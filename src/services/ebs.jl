include("../AWSServices.jl")
using .AWSServices: ebs

"""
    ListChangedBlocks()

Returns the block indexes and block tokens for blocks that are different between two Amazon Elastic Block Store snapshots of the same volume/snapshot lineage.

Required Parameters
{
  "SecondSnapshotId": "The ID of the second snapshot to use for the comparison.  The SecondSnapshotId parameter must be specified with a FirstSnapshotID parameter; otherwise, an error occurs. "
}

Optional Parameters
{
  "MaxResults": "The number of results to return.",
  "StartingBlockIndex": "The block index from which the comparison should start. The list in the response will start from this block index or the next valid block index in the snapshots.",
  "NextToken": "The token to request the next page of results.",
  "FirstSnapshotId": "The ID of the first snapshot to use for the comparison.  The FirstSnapshotID parameter must be specified with a SecondSnapshotId parameter; otherwise, an error occurs. "
}
"""
ListChangedBlocks(args) = ebs("GET", "/snapshots/{secondSnapshotId}/changedblocks", args)

"""
    GetSnapshotBlock()

Returns the data in a block in an Amazon Elastic Block Store snapshot.

Required Parameters
{
  "SnapshotId": "The ID of the snapshot containing the block from which to get data.",
  "BlockIndex": "The block index of the block from which to get data. Obtain the BlockIndex by running the ListChangedBlocks or ListSnapshotBlocks operations.",
  "BlockToken": "The block token of the block from which to get data. Obtain the BlockToken by running the ListChangedBlocks or ListSnapshotBlocks operations."
}
"""
GetSnapshotBlock(args) = ebs("GET", "/snapshots/{snapshotId}/blocks/{blockIndex}", args)

"""
    ListSnapshotBlocks()

Returns the block indexes and block tokens for blocks in an Amazon Elastic Block Store snapshot.

Required Parameters
{
  "SnapshotId": "The ID of the snapshot from which to get block indexes and block tokens."
}

Optional Parameters
{
  "MaxResults": "The number of results to return.",
  "StartingBlockIndex": "The block index from which the list should start. The list in the response will start from this block index or the next valid block index in the snapshot.",
  "NextToken": "The token to request the next page of results."
}
"""
ListSnapshotBlocks(args) = ebs("GET", "/snapshots/{snapshotId}/blocks", args)