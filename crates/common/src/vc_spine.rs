use flux::{communication::ShmemData, spine_derive::from_spine, tile::TileInfo};

#[from_spine("silver_vc")]
#[derive(Debug)]
pub struct VcSpine {
    pub tile_info: ShmemData<TileInfo>,
}
