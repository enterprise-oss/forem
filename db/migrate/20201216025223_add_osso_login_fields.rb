class AddOssoLoginFields < ActiveRecord::Migration[6.0]
  def change
    add_column :users, :osso_username, :string
    add_column :users, :osso_created_at, :datetime
  end
end
